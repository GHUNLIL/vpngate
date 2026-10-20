package main

// Exit pool (EXITS=N): N extra tunnels, each behind its own SOCKS5 port (EXIT_PORT, EXIT_PORT+1, ...).
// Unlike the Shadowsocks entry, an exit is sticky: it keeps its node for as long as the node works
// and is replaced only when the tunnel dies or its loss stays above EXIT_MAX_LOSS. There is no hold
// period or re-ranking, and a restart reconnects every port to the node it had. Every exit, the
// active and the standby use different IPs, so per-account proxies get distinct exit IPs.

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"sort"
	"sync"
	"time"
)

// ExitRoute returns the device for exit i, or "" while it has no working tunnel. It never falls
// back to another exit: a request through port i always leaves from exit i's IP or fails.
func (m *Manager) ExitRoute(i int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t := m.exits[i]; t != nil && t.Alive() {
		return t.Dev
	}
	return ""
}

// exitHolding returns the index of the exit using n, or -1 (caller holds m.mu).
func (m *Manager) exitHolding(n *Node) int {
	for i, t := range m.exits {
		if t != nil && t.Node == n {
			return i
		}
	}
	return -1
}

// missingExits lists exit indexes without a working tunnel (caller holds m.mu).
func (m *Manager) missingExits() []int {
	var out []int
	for i, t := range m.exits {
		if t == nil || !t.Alive() {
			out = append(out, i)
		}
	}
	return out
}

// ipTaken reports whether n's IP or exit IP is already used by another tunnel (caller holds m.mu).
func (m *Manager) ipTaken(n *Node, except *Tunnel) bool {
	for _, t := range m.tunnels() {
		if t == except || t.Node == n {
			continue
		}
		for _, ip := range []string{n.IP, n.ExitIP} {
			if ip != "" && (ip == t.Node.IP || ip == t.Node.ExitIP) {
				return true
			}
		}
	}
	return false
}

// tunnels returns every tunnel in service: active, standby and exits (caller holds m.mu).
func (m *Manager) tunnels() []*Tunnel {
	var out []*Tunnel
	for _, t := range append([]*Tunnel{m.active, m.standby}, m.exits...) {
		if t != nil {
			out = append(out, t)
		}
	}
	return out
}

// adoptExit installs t as exit i if the slot is still empty and its IP is still free (caller holds m.mu).
func (m *Manager) adoptExit(i int, t *Tunnel, reason string) bool {
	if m.closing || m.exits[i] != nil && m.exits[i].Alive() || m.ipTaken(t.Node, t) {
		return false
	}
	if old := m.exits[i]; old != nil {
		m.release(old)
	}
	m.exits[i] = t
	log.Printf("出口 %d (端口 %d): %s，%s", i+1, m.cfg.ExitPort+i, exitIPOf(t.Node), reason)
	m.saveState()
	return true
}

func exitIPOf(n *Node) string {
	if n.ExitIP != "" {
		return n.ExitIP
	}
	return n.IP
}

// restoreExits reconnects each port to the node it had before the restart.
func (m *Manager) restoreExits(ctx context.Context, saved []*Node) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, m.cfg.DeepTestParallel)
	for i, n := range saved {
		if i >= len(m.exits) || n == nil || n.Config == "" || !m.transportOK(n) {
			continue
		}
		m.mu.Lock()
		if m.ipTaken(n, nil) {
			m.mu.Unlock()
			continue // already restored as the active node
		}
		m.nodes[n.ID] = n
		m.mu.Unlock()
		wg.Add(1)
		go func(i int, n *Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t := m.evaluate(ctx, n)
			if t == nil {
				log.Printf("出口 %d: 上次的节点 %s 已不可用，稍后换新节点", i+1, n.IP)
				return
			}
			m.mu.Lock()
			if !m.adoptExit(i, t, "重启后恢复") {
				m.release(t)
			}
			m.mu.Unlock()
		}(i, n)
	}
	wg.Wait()
}

// ensureExits fills empty exits. Candidates are the better-connected half of the pool in random
// order, so the exits spread over many home lines instead of always the same few fastest ones.
// No speed test: an exit only needs to work, and the test would cost 4 MB per candidate.
func (m *Manager) ensureExits(ctx context.Context) {
	m.mu.Lock()
	missing := m.missingExits()
	if len(missing) == 0 {
		m.mu.Unlock()
		return
	}
	cands := m.eligible()
	sort.Slice(cands, func(i, j int) bool { return cands[i].PrefilterKey() < cands[j].PrefilterKey() })
	m.mu.Unlock()
	if keep := max(len(cands)/2, 3*len(missing)); keep < len(cands) {
		cands = cands[:keep]
	}
	rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	if len(cands) == 0 {
		log.Printf("出口池: 没有可用的候选节点，%d 个出口暂时空缺", len(missing))
		return
	}
	log.Printf("出口池: 为 %d 个空缺出口测试候选节点", len(missing))

	batch := m.cfg.DeepTestParallel
	for len(cands) > 0 && len(missing) > 0 && ctx.Err() == nil {
		n := min(batch, len(cands), len(missing)+1)
		results := make([]*Tunnel, n)
		var wg sync.WaitGroup
		for k := 0; k < n; k++ {
			wg.Add(1)
			go func(k int, node *Node) {
				defer wg.Done()
				results[k] = m.evaluate(ctx, node)
			}(k, cands[k])
		}
		wg.Wait()
		cands = cands[n:]
		m.mu.Lock()
		for _, t := range results {
			if t == nil {
				continue
			}
			if len(missing) > 0 && val(t.Node.Loss) <= m.cfg.ExitMaxLoss && m.adoptExit(missing[0], t, "新分配") {
				missing = missing[1:]
				continue
			}
			m.release(t)
		}
		m.mu.Unlock()
	}
	if len(missing) > 0 {
		log.Printf("出口池: 还有 %d 个出口空缺，1 分钟后重试", len(missing))
	}
}

// checkExits replaces exits whose tunnel died or whose network stays bad (caller holds m.mu).
// A brief loss spike is tolerated: the IP only changes when the recent average is over the limit.
func (m *Manager) checkExits() {
	for i, t := range m.exits {
		if t == nil {
			continue
		}
		l := t.Live.Loss
		var reason string
		switch {
		case !t.Alive():
			reason = "OpenVPN 进程退出: " + tail(t.LastLog(), 80)
		case dead(l):
			reason = "连续 3 轮检测无响应"
		case len(l) >= liveRounds && mean(l) > m.cfg.ExitMaxLoss:
			reason = fmt.Sprintf("最近 30 秒丢包 %.1f%%", mean(l))
		default:
			continue
		}
		log.Printf("出口 %d (端口 %d) 节点 %s 不可用: %s，更换新 IP", i+1, m.cfg.ExitPort+i, t.Node.IP, reason)
		t.Node.Error = reason
		t.Node.FailedUntil = time.Now().Add(degradedBackoff).Unix()
		m.exits[i] = nil
		m.release(t)
		m.saveState()
		m.RequestRefresh()
	}
}
