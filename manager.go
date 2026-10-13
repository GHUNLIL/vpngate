package main

// Node selection, active/standby tunnels, health monitoring and failover.
//
// Pipeline: fetch list -> keep JP residential -> stage 1: direct RTT from the VPS (cheap, every node)
// -> stage 2: real tunnels for the top N, measuring RTT / jitter / loss / throughput through them
// -> best becomes active, runner-up stays connected as a warm standby for instant failover.
//
// Selection rule (Better): speed >= MIN_MBPS qualifies, then lowest latency wins. The active node is
// kept for HOLD_MINUTES so the exit IP is stable, then everything is re-measured and re-ranked.
// Failures never wait for the hold: they fail over to the standby immediately.
//
// Rotation mode (ROTATE_NO_REPEAT=1): every hold period moves to an exit IP that has not been used
// yet. Used IPs are left out of the candidates until every node is either used or failing; then the
// record is cleared and the rotation starts over.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	failBackoff     = 30 * time.Minute // node failed to connect
	degradedBackoff = 10 * time.Minute // node connected but went bad
	speedtestURL    = "https://speed.cloudflare.com/__down?bytes=%d"
	exitInfoURL     = "http://ip-api.com/json/?fields=query"

	// Deep tests ping with probeSize bytes (close to real traffic). The real-time monitor uses small
	// monitorProbeSize pings to keep its own traffic low (~0.1 GB/day); large-packet problems are
	// caught by the per-tunnel MTU probe, re-run every mtuRecheck rounds.
	probeSize        = 1200
	monitorProbeSize = 56
	mtuRecheck       = 300 // ~10 min at 2 s
	listMaxAge       = 3 * time.Hour
	probeCount       = 5
	liveRounds       = 15 // rounds kept per tunnel (~30 s at 2 s)
	minRounds        = 6  // rounds needed before a loss-based switch (~12 s, 30 packets)
)

type Manager struct {
	cfg     *Config
	res     *Resolver
	version [2]int
	auth    string

	mu          sync.RWMutex // guards everything below, including Node fields
	nodes       map[string]*Node
	active      *Tunnel
	standby     *Tunnel
	lockedID    string // user-pinned node: keep this exit IP
	closing     bool
	exitIP      string // last announced exit IP, for change notifications
	down        bool   // no usable node; announced once until recovery
	notify      *Notifier
	activeSince time.Time
	status      string
	lastRefresh int64
	slots       []int
	used        map[string]bool // rotation mode: node / exit IPs already used this round

	selectMu sync.Mutex // serialises selection / switching
	wake     chan struct{}
}

func NewManager(cfg *Config) *Manager {
	m := &Manager{cfg: cfg, res: NewResolver(cfg.DNSServers), nodes: map[string]*Node{}, used: map[string]bool{},
		notify: &Notifier{WebhookURL: cfg.NotifyWebhook, TGToken: cfg.TGBotToken, TGChatID: cfg.TGChatID},
		status: "启动中", wake: make(chan struct{}, 1), auth: filepath.Join(cfg.DataDir, "auth.txt")}
	for i := 0; i < maxSlots; i++ {
		m.slots = append(m.slots, i)
	}
	return m
}

// Route returns the device for new proxy connections; it falls through to the standby the
// instant the active tunnel dies, before the monitor even notices.
func (m *Manager) Route() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range []*Tunnel{m.active, m.standby} {
		if t != nil && t.Alive() {
			return t.Dev
		}
	}
	return ""
}

func (m *Manager) Start(ctx context.Context) error {
	if err := os.MkdirAll(m.cfg.RunDir(), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(m.auth, []byte("vpn\nvpn\n"), 0o600); err != nil {
		return err
	}
	v, err := OpenVPNVersion(m.cfg.OpenVPN)
	if err != nil {
		return err
	}
	m.version = v
	log.Printf("OpenVPN %d.%d", v[0], v[1])
	CleanupStale(m.cfg.RunDir())

	var state struct {
		LockedID    string   `json:"locked_id"`
		Last        *Node    `json:"last"`
		ActiveSince int64    `json:"active_since"`
		ExitIP      string   `json:"exit_ip"`
		Used        []string `json:"used"`
	}
	if data, err := os.ReadFile(m.statePath()); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	m.lockedID = state.LockedID
	m.exitIP = state.ExitIP
	if m.cfg.NoRepeat {
		for _, ip := range state.Used {
			m.used[ip] = true
		}
	}
	if state.Last != nil && state.Last.Config != "" && m.transportOK(state.Last) {
		m.nodes[state.Last.ID] = state.Last
		log.Printf("尝试恢复上次使用的节点 %s (保持出口 IP 不变)", state.Last.IP)
		if t := m.evaluate(ctx, state.Last); t != nil {
			m.mu.Lock()
			m.setActive(t, "重启后恢复")
			if state.ActiveSince > 0 { // a restart does not reset the hold period
				m.activeSince = time.Unix(state.ActiveSince, 0)
				m.saveState()
			}
			m.mu.Unlock()
		}
	}
	return nil
}

func (m *Manager) Run(ctx context.Context) {
	go m.monitor(ctx)
	for {
		select {
		case <-m.wake:
		default:
		}
		// The list (~1.3 MB) is only fetched when a selection is due, or when it is getting old.
		// Rotation reselects every few minutes, so there it is fetched at most every REFRESH_MINUTES.
		age := time.Since(time.Unix(m.lastRefreshed(), 0))
		due := m.selectionDue() && (!m.cfg.NoRepeat || age > m.cfg.Refresh || !m.hasActive())
		if due || age > listMaxAge {
			if err := m.refresh(ctx); err != nil {
				log.Printf("刷新节点列表失败: %v", err)
			}
		}
		m.selectMu.Lock()
		m.ensure(ctx)
		m.selectMu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-time.After(m.nextWake()):
		}
	}
}

// nextWake is the time until the next list refresh or hold expiry, whichever comes first.
func (m *Manager) nextWake() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil || !m.active.Alive() {
		return time.Minute
	}
	wait := m.cfg.Refresh
	if m.lockedID == "" {
		if left := time.Until(m.activeSince.Add(m.cfg.Hold)); left < wait {
			wait = max(left, 10*time.Second)
		}
	}
	return wait
}

// selectionDue reports whether ensure will need candidates: no active, no standby, a pinned node to
// return to, or the hold period is over.
func (m *Manager) selectionDue() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil || !m.active.Alive() || m.cfg.Standby && (m.standby == nil || !m.standby.Alive()) {
		return true
	}
	if pinned := m.nodes[m.lockedID]; pinned != nil && m.active.Node != pinned {
		return true
	}
	return m.lockedID == "" && (time.Since(m.activeSince) >= m.cfg.Hold || !m.transportOK(m.active.Node))
}

func (m *Manager) hasActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active != nil && m.active.Alive()
}

func (m *Manager) lastRefreshed() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRefresh
}

func (m *Manager) RequestRefresh() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// SwitchTo is a manual switch from the UI. It pins the node so the exit IP stays fixed.
func (m *Manager) SwitchTo(ctx context.Context, id string) error {
	m.selectMu.Lock()
	defer m.selectMu.Unlock()
	m.mu.Lock()
	n := m.nodes[id]
	if n == nil {
		m.mu.Unlock()
		return fmt.Errorf("节点不存在")
	}
	if m.active != nil && m.active.Node == n {
		m.lockedID = id
		m.saveState()
		m.mu.Unlock()
		return nil
	}
	var t *Tunnel
	if m.standby != nil && m.standby.Node == n && m.standby.Alive() {
		t, m.standby = m.standby, nil
	}
	n.FailedUntil = 0
	m.mu.Unlock()
	if t == nil {
		if t = m.evaluate(ctx, n); t == nil {
			m.mu.RLock()
			defer m.mu.RUnlock()
			return fmt.Errorf("连接失败: %s", n.Error)
		}
		mbps := m.speedtest(ctx, t)
		m.mu.Lock()
		n.Mbps = mbps
		m.mu.Unlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.promote(t, "手动切换")
	m.lockedID = id
	m.saveState()
	return nil
}

func (m *Manager) SetLocked(locked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockedID = ""
	if locked && m.active != nil {
		m.lockedID = m.active.Node.ID
	}
	m.saveState()
}

func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.closing = true // from here on nothing is adopted or saved
	tunnels := []*Tunnel{m.active, m.standby}
	m.active, m.standby = nil, nil
	m.mu.Unlock()
	for _, t := range tunnels {
		if t != nil {
			t.Stop()
		}
	}
}

// ---------------------------------------------------------------- node list

func (m *Manager) refresh(ctx context.Context) error {
	data, err := FetchCSV(ctx, m.cfg.Sources, filepath.Join(m.cfg.DataDir, "servers.csv"))
	if err != nil {
		return err
	}
	fresh := ParseCSV(data, m.cfg.Countries)
	if m.cfg.Transport != "tcp" {
		fresh = WithUDP(fresh, FetchUDPPorts(ctx, filepath.Join(m.cfg.DataDir, "udp_ports.json")))
	}
	ClassifyNodes(ctx, fresh, filepath.Join(m.cfg.DataDir, "ipinfo.json"))

	m.mu.Lock()
	merged := make(map[string]*Node, len(fresh))
	kinds := map[string]int{}
	for _, n := range fresh {
		kinds[n.Kind+"/"+n.Proto]++
		if old := m.nodes[n.ID]; old != nil { // keep measurements across refreshes
			n.HandshakeMs, n.RTT, n.Jitter, n.Loss, n.Mbps = old.HandshakeMs, old.RTT, old.Jitter, old.Loss, old.Mbps
			n.ConnMs = old.ConnMs
			n.ExitIP, n.TestedAt, n.Error, n.FailedUntil = old.ExitIP, old.TestedAt, old.Error, old.FailedUntil
		}
		merged[n.ID] = n
	}
	for _, t := range []*Tunnel{m.active, m.standby} { // in-use nodes may have dropped off the list
		if t != nil {
			merged[t.Node.ID] = t.Node
		}
	}
	if old := m.nodes[m.lockedID]; old != nil && merged[m.lockedID] == nil {
		merged[m.lockedID] = old
	}
	m.nodes = merged
	pool := m.pool()
	m.mu.Unlock()

	m.prefilter(ctx, pool)
	m.mu.Lock()
	m.lastRefresh = time.Now().Unix()
	m.mu.Unlock()
	var parts []string
	for k, v := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(parts)
	log.Printf("节点列表: %d 个 (%s)", len(fresh), strings.Join(parts, ", "))
	return nil
}

// pool returns usable candidates (caller holds m.mu). In rotation mode used nodes still count when
// deciding whether to fall back to other node types or protocols, and are only left out at the end:
// running out of fresh residential IPs starts a new round instead of falling back.
func (m *Manager) pool() []*Node {
	nodes := m.eligible()
	if !m.cfg.NoRepeat {
		return nodes
	}
	var fresh []*Node
	for _, n := range nodes {
		if !m.isUsed(n) {
			fresh = append(fresh, n)
		}
	}
	return fresh
}

func (m *Manager) eligible() []*Node {
	now := time.Now()
	var all, home []*Node
	for _, n := range m.nodes {
		if n.Failed(now) || m.inUse(n) {
			continue
		}
		all = append(all, n)
		if n.Kind == "residential" || n.Kind == "unknown" {
			home = append(home, n)
		}
	}
	nodes := home
	if !m.cfg.ResidentialOnly {
		nodes = all
	} else if len(home) == 0 && len(all) > 0 {
		log.Printf("没有可用的家宽节点，临时使用其他类型节点")
		nodes = all
	}
	var native []*Node
	for _, n := range nodes {
		if m.transportOK(n) {
			native = append(native, n)
		}
	}
	if len(native) == 0 && len(nodes) > 0 {
		log.Printf("没有可用的 %s 节点，临时使用其他协议", strings.ToUpper(m.cfg.Transport))
		return nodes
	}
	return native
}

// transportOK reports whether n uses the configured transport (TRANSPORT=udp / tcp; auto takes both).
func (m *Manager) transportOK(n *Node) bool {
	return m.cfg.Transport == "auto" || n.Proto == m.cfg.Transport
}

func (m *Manager) inUse(n *Node) bool {
	return m.active != nil && m.active.Node == n || m.standby != nil && m.standby.Node == n
}

// isUsed reports whether rotation has already used this node's IP or exit IP (caller holds m.mu).
func (m *Manager) isUsed(n *Node) bool {
	return m.used[n.IP] || n.ExitIP != "" && m.used[n.ExitIP]
}

// markUsed records the node for rotation (caller holds m.mu).
func (m *Manager) markUsed(n *Node) {
	if !m.cfg.NoRepeat {
		return
	}
	m.used[n.IP] = true
	if n.ExitIP != "" {
		m.used[n.ExitIP] = true
	}
}

// resetUsed starts a new rotation round once every node is used or failing. The current active
// stays recorded so the next pick is still a different IP (caller holds m.mu).
func (m *Manager) resetUsed() {
	log.Printf("所有节点都已轮换过或不可用 (已用 %d 个 IP)，清空记录重新轮换", len(m.used))
	m.used = map[string]bool{}
	if m.active != nil {
		m.markUsed(m.active.Node)
	}
	m.saveState()
}

// prefilter is stage 1: direct RTT from the VPS to every candidate (TCP connect, or an OpenVPN
// handshake probe for UDP).
func (m *Manager) prefilter(ctx context.Context, nodes []*Node) {
	type result struct {
		rtt *float64
		ok  bool
	}
	results := make([]result, len(nodes))
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, ip string, port int, proto string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if proto == "tcp" {
				a := TCPRTT(ctx, ip, port, "", 2*time.Second)
				b := TCPRTT(ctx, ip, port, "", 2*time.Second)
				if a == nil || b != nil && *b < *a {
					a = b
				}
				results[i] = result{a, a != nil}
				return
			}
			a := OpenVPNUDPRTT(ip, port, 1500*time.Millisecond)
			b := OpenVPNUDPRTT(ip, port, 1500*time.Millisecond)
			if a == nil || b != nil && *b < *a {
				a = b
			}
			results[i] = result{a, a != nil}
		}(i, n.IP, n.Port, n.Proto)
	}
	wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, n := range nodes {
		n.DirectRTT = results[i].rtt
		if !results[i].ok {
			n.FailedUntil = time.Now().Add(degradedBackoff).Unix()
			n.Error = "端口不可达"
		}
	}
}

// ---------------------------------------------------------------- selection

func (m *Manager) ensure(ctx context.Context) {
	m.restoreLocked(ctx)
	m.mu.RLock()
	needActive := m.active == nil || !m.active.Alive()
	needStandby := m.cfg.Standby && (m.standby == nil || !m.standby.Alive())
	// A node on the wrong transport (e.g. TCP after switching to TRANSPORT=udp) is replaced right away.
	reselect := !needActive && m.lockedID == "" &&
		(time.Since(m.activeSince) >= m.cfg.Hold || !m.transportOK(m.active.Node))
	m.mu.RUnlock()
	if !needActive && !needStandby && !reselect {
		return
	}
	m.setStatus("正在测试节点")
	tunnels := m.acquire(ctx)
	if ctx.Err() != nil { // shutting down mid-test: keep the saved node, adopt nothing
		m.mu.Lock()
		for _, t := range tunnels {
			m.release(t)
		}
		m.mu.Unlock()
		return
	}
	if reselect {
		m.reselect(ctx, tunnels)
		return
	}
	m.mu.Lock()
	if (m.active == nil || !m.active.Alive()) && len(tunnels) > 0 {
		if m.active != nil {
			m.release(m.active)
		}
		m.setActive(tunnels[0], "选出新节点")
		tunnels = tunnels[1:]
	}
	if m.cfg.Standby && (m.standby == nil || !m.standby.Alive()) && len(tunnels) > 0 {
		if m.standby != nil {
			m.release(m.standby)
		}
		m.standby = tunnels[0]
		tunnels = tunnels[1:]
		log.Printf("备用节点: %s", describe(m.standby.Node))
	}
	for _, t := range tunnels {
		m.release(t)
	}
	if m.active != nil {
		m.status = "运行中"
	} else {
		m.status = "没有可用节点，1 分钟后重试"
		m.markDown("没有可用节点")
	}
	m.mu.Unlock()
}

// reselect runs when the hold period ends: the current active and standby are re-measured
// (including speed) and compete with the fresh candidates under the same rule. The winner becomes
// active, the runner-up the standby. A replaced active keeps its tunnel for a minute so open
// connections can finish.
func (m *Manager) reselect(ctx context.Context, fresh []*Tunnel) {
	m.mu.RLock()
	var incumbents []*Tunnel
	used := map[*Tunnel]bool{}
	for _, t := range []*Tunnel{m.active, m.standby} {
		if t != nil && t.Alive() {
			incumbents = append(incumbents, t)
			used[t] = m.cfg.NoRepeat && m.isUsed(t.Node)
		}
	}
	m.mu.RUnlock()
	all := append([]*Tunnel(nil), fresh...)
	for _, t := range incumbents {
		if len(fresh) > 0 && !m.transportOK(t.Node) {
			continue // replaced by a node on the configured transport
		}
		if used[t] {
			continue // rotation: the current exit IP never wins again this round
		}
		if m.measure(ctx, t) == nil {
			all = append(all, t)
		}
	}
	m.rankWithSpeed(ctx, all)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = "运行中"
	log.Printf("定时重选排名 (速度 ≥ %.0f Mbps 合格，合格中延迟最低者优先):", m.cfg.MinMbps)
	for i, t := range all {
		tag := ""
		switch t {
		case m.active:
			tag = " [当前]"
		case m.standby:
			tag = " [备用]"
		}
		log.Printf("  %d. %s%s", i+1, describe(t.Node), tag)
	}
	var best, second *Tunnel
	for _, t := range all {
		switch {
		case !t.Alive():
		case best == nil:
			best = t
		case second == nil && m.cfg.Standby:
			second = t
		}
	}
	if best == nil {
		retry := min(10*time.Minute, m.cfg.Hold)
		log.Printf("定时重选: 没有可用节点，保持现状，%d 分钟后重试", int(retry.Minutes()))
		m.activeSince = time.Now().Add(retry - m.cfg.Hold)
		return
	}
	old := m.active
	seen := map[*Tunnel]bool{}
	for _, t := range append(all, incumbents...) {
		if seen[t] || t == best || t == second {
			continue
		}
		seen[t] = true
		if t == old {
			m.active = nil
			m.drain(t)
		} else {
			m.release(t)
		}
	}
	m.standby = second
	if best == old {
		log.Printf("定时重选: 当前节点仍是最优，保持出口 IP %s", best.Node.IP)
		m.activeSince = time.Now()
		m.saveState()
	} else if m.cfg.NoRepeat {
		log.Printf("定时轮换: 切换到未用过的出口 IP (本轮已用 %d 个)", len(m.used))
		m.setActive(best, fmt.Sprintf("%d 分钟定时轮换", int(m.cfg.Hold.Minutes())))
	} else {
		log.Printf("定时重选: 切换到更优节点")
		m.setActive(best, fmt.Sprintf("%d 分钟定时重选", int(m.cfg.Hold.Minutes())))
	}
	if second != nil {
		log.Printf("备用节点: %s", describe(second.Node))
	}
}

// sortTunnels orders tunnels best first by the selection rule (caller holds m.mu).
func (m *Manager) sortTunnels(ts []*Tunnel) {
	sort.SliceStable(ts, func(i, j int) bool { return Better(ts[i].Node, ts[j].Node, m.cfg.MinMbps) })
}

// drain keeps a replaced tunnel up briefly for connections already using it; new connections
// already go to the new active.
func (m *Manager) drain(t *Tunnel) {
	go func() {
		time.Sleep(time.Minute)
		m.mu.Lock()
		m.release(t)
		m.mu.Unlock()
	}()
}

// restoreLocked moves back to the pinned node once it recovers from a failover.
func (m *Manager) restoreLocked(ctx context.Context) {
	m.mu.Lock()
	n := m.nodes[m.lockedID]
	if n == nil || m.active != nil && m.active.Node == n || n.Failed(time.Now()) {
		m.mu.Unlock()
		return
	}
	var t *Tunnel
	if m.standby != nil && m.standby.Node == n && m.standby.Alive() {
		t, m.standby = m.standby, nil
	}
	m.mu.Unlock()
	if t == nil {
		t = m.evaluate(ctx, n)
	}
	if t != nil {
		m.mu.Lock()
		m.promote(t, "恢复锁定节点")
		m.mu.Unlock()
	}
}

// acquire is stage 2: deep-test the top candidates in parallel; returns working tunnels, best first.
func (m *Manager) acquire(ctx context.Context) []*Tunnel {
	m.mu.Lock()
	cands := m.pool()
	if len(cands) == 0 && m.cfg.NoRepeat && len(m.used) > 0 {
		m.resetUsed()
		cands = m.pool()
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].PrefilterKey() < cands[j].PrefilterKey() })
	m.mu.Unlock()
	if len(cands) > m.cfg.DeepTestCount {
		cands = cands[:m.cfg.DeepTestCount]
	}
	if len(cands) == 0 {
		return nil
	}
	log.Printf("深度测试 %d 个候选节点", len(cands))
	results := make([]*Tunnel, len(cands))
	sem := make(chan struct{}, m.cfg.DeepTestParallel)
	var wg sync.WaitGroup
	for i, n := range cands {
		wg.Add(1)
		go func(i int, n *Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = m.evaluate(ctx, n)
		}(i, n)
	}
	wg.Wait()
	var tunnels []*Tunnel
	for _, t := range results {
		if t != nil {
			tunnels = append(tunnels, t)
		}
	}
	m.rankWithSpeed(ctx, tunnels)
	m.mu.RLock()
	for _, t := range tunnels {
		log.Printf("  %s", describe(t.Node))
	}
	m.mu.RUnlock()
	return tunnels
}

// rankWithSpeed applies the rule with as few speed tests as possible: tunnels are tried in latency
// order (loss-free first) and speed-tested only until enough of them qualify for active + standby.
// The rest get no speed figure this round, which ranks them below the qualified ones.
func (m *Manager) rankWithSpeed(ctx context.Context, ts []*Tunnel) {
	need := 1
	if m.cfg.Standby {
		need = 2
	}
	m.mu.Lock()
	for _, t := range ts {
		t.Node.Mbps = nil
	}
	sort.SliceStable(ts, func(i, j int) bool {
		a, b := ts[i].Node, ts[j].Node
		if la, lb := val(a.Loss) <= maxQualifiedLoss, val(b.Loss) <= maxQualifiedLoss; la != lb {
			return la
		}
		return a.Latency() < b.Latency()
	})
	m.mu.Unlock()
	found := 0
	for _, t := range ts {
		m.mu.RLock()
		lossOK := val(t.Node.Loss) <= maxQualifiedLoss
		m.mu.RUnlock()
		if found >= need || !lossOK || m.cfg.SpeedtestBytes == 0 {
			break
		}
		mbps := m.speedtest(ctx, t)
		m.mu.Lock()
		t.Node.Mbps = mbps
		if t.Node.Qualified(m.cfg.MinMbps) {
			found++
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.sortTunnels(ts)
	m.mu.Unlock()
}

func (m *Manager) speedtest(ctx context.Context, t *Tunnel) *float64 {
	if m.cfg.SpeedtestBytes == 0 {
		return nil
	}
	v, err := SpeedTest(ctx, m.res, fmt.Sprintf(speedtestURL, m.cfg.SpeedtestBytes), t.Dev, m.cfg.SpeedtestBytes/4)
	if err != nil {
		return nil
	}
	return ptr(v)
}

func (m *Manager) evaluate(ctx context.Context, n *Node) *Tunnel {
	m.mu.Lock()
	if len(m.slots) == 0 {
		m.mu.Unlock()
		return nil
	}
	slot := m.slots[0]
	m.slots = m.slots[1:]
	m.mu.Unlock()

	t := NewTunnel(n, slot, m.cfg.RunDir())
	// A healthy handshake takes ~1.3 s over UDP and ~2.5 s over TCP; don't let dead nodes stall recovery.
	hs, err := t.Start(ctx, m.cfg.OpenVPN, m.auth, m.version, 10*time.Second)
	if err == nil {
		m.mu.Lock()
		n.HandshakeMs = ptr(hs)
		m.mu.Unlock()
		err = m.measure(ctx, t)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		n.Error = err.Error()
		n.FailedUntil = time.Now().Add(failBackoff).Unix()
		log.Printf("节点 %s 不可用: %s", n.IP, n.Error)
		m.release(t)
		return nil
	}
	n.Error = ""
	return t
}

// probeMTU finds the largest inner packet this node's path actually delivers and sets the device
// MTU to it. Paths differ (PPPoE, MAP-E, DS-Lite...): oversized packets are silently dropped, so
// a right-sized MTU lets the kernel size TCP segments and UDP datagrams to fit.
func (m *Manager) probeMTU(ctx context.Context, t *Tunnel) int {
	mtu := 1280
	for _, size := range []int{1400, 1380, 1360, 1340, 1320, 1300} {
		if st := Ping(ctx, m.cfg.ProbeTarget, 3, size-28, 50*time.Millisecond, time.Second, t.Dev); len(st.RTTs) >= 2 {
			mtu = size
			break
		}
	}
	_ = ipCmd("link", "set", "dev", t.Dev, "mtu", strconv.Itoa(mtu))
	return mtu
}

// measure records MTU, latency, jitter, loss and exit IP through the tunnel (speed is separate).
func (m *Manager) measure(ctx context.Context, t *Tunnel) error {
	mtu := m.probeMTU(ctx, t)
	st := Ping(ctx, m.cfg.ProbeTarget, 20, probeSize, 100*time.Millisecond, time.Second, t.Dev)
	probe := "icmp"
	if len(st.RTTs) == 0 { // some nodes drop ICMP: fall back to TCP handshakes
		st, probe = m.tcpProbe(ctx, t.Dev, 3), "tcp"
	}
	if ctx.Err() != nil {
		return ctx.Err() // shutting down: the samples are meaningless
	}
	if len(st.RTTs) == 0 {
		return fmt.Errorf("隧道已建立但无法访问外网")
	}
	if loss := st.LossPct(); loss > 50 {
		return fmt.Errorf("隧道内丢包 %.0f%%", loss)
	}
	var exitIP string
	if body, err := HTTPGet(ctx, m.res, exitInfoURL, t.Dev); err == nil {
		var info struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(body, &info) == nil {
			exitIP = info.Query
		}
	}
	connMs, connLoss, err := m.connectTest(ctx, t)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := t.Node
	t.Probe = probe
	n.MTU = mtu
	n.RTT, n.Jitter, n.Loss = st.Avg(), ptr(st.Jitter()), ptr(max(st.LossPct(), connLoss))
	n.ConnMs = connMs
	n.TestedAt = time.Now().Unix()
	if exitIP != "" {
		n.ExitIP = exitIP
	}
	return nil
}

// connectTest makes CONNECT_TEST_COUNT real requests to CONNECT_TEST_URL through the tunnel. A node
// none of them get through is unusable; failed attempts count as loss, and the median request time
// becomes the latency used for ranking. Off (nil, 0) when no URL is set.
func (m *Manager) connectTest(ctx context.Context, t *Tunnel) (*float64, float64, error) {
	url, count := m.cfg.ConnectTestURL, m.cfg.ConnectTestCount
	if url == "" {
		return nil, 0, nil
	}
	var times []float64
	var lastErr error
	for i := 0; i < count; i++ {
		ms, err := ConnectTest(ctx, m.res, url, t.Dev, 6*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		times = append(times, ms)
	}
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	if len(times) == 0 {
		return nil, 0, fmt.Errorf("真连接测试失败: %v", lastErr)
	}
	sort.Float64s(times)
	return ptr(times[len(times)/2]), 100 * float64(count-len(times)) / float64(count), nil
}

func (m *Manager) tcpProbe(ctx context.Context, dev string, count int) PingStats {
	st := PingStats{Sent: count}
	for i := 0; i < count; i++ {
		if r := TCPRTT(ctx, m.cfg.ProbeTarget, 443, dev, 2*time.Second); r != nil {
			st.RTTs = append(st.RTTs, *r)
		}
	}
	return st
}

// ---------------------------------------------------------------- switching (caller holds m.mu)

func (m *Manager) setActive(t *Tunnel, reason string) {
	if m.closing {
		m.release(t)
		return
	}
	m.active = t
	m.activeSince = time.Now()
	m.markUsed(t.Node)
	log.Printf("当前节点: %s", describe(t.Node))
	m.announce(t.Node, reason)
	m.saveState()
}

// announce notifies when the exit IP changes or service comes back (caller holds m.mu).
func (m *Manager) announce(n *Node, reason string) {
	ip := n.ExitIP
	if ip == "" {
		ip = n.IP
	}
	old := m.exitIP
	m.exitIP = ip
	node := fmt.Sprintf("%s %s %s", n.IP, n.ISP, strings.ToUpper(n.Proto))
	switch {
	case m.down:
		m.down = false
		m.notify.Send(Event{Event: "recovered", OldIP: old, NewIP: ip, Reason: reason, Node: node,
			Text: fmt.Sprintf("已恢复，出口 IP %s (%s)", ip, n.ISP)})
	case old != "" && old != ip && !m.cfg.NoRepeat: // in rotation mode IP changes are the point, not news
		m.notify.Send(Event{Event: "exit_ip_changed", OldIP: old, NewIP: ip, Reason: reason, Node: node,
			Text: fmt.Sprintf("出口 IP 变更 %s → %s，原因: %s (%s)", old, ip, reason, n.ISP)})
	}
}

// markDown announces an outage once (caller holds m.mu).
func (m *Manager) markDown(reason string) {
	if m.down || m.closing {
		return
	}
	m.down = true
	log.Printf("服务中断: %s", reason)
	m.notify.Send(Event{Event: "no_node", OldIP: m.exitIP, Reason: reason, Text: "服务中断: " + reason})
}

// promote is make-before-break: the old active becomes the standby so open connections survive.
func (m *Manager) promote(t *Tunnel, reason string) {
	old := m.active
	m.setActive(t, reason)
	log.Printf("切换原因: %s", reason)
	if old != nil && old.Alive() && m.cfg.Standby {
		if m.standby != nil {
			m.release(m.standby)
		}
		m.standby = old
	} else if old != nil {
		m.release(old)
	}
}

func (m *Manager) failover(reason string) {
	old := m.active
	if old == nil {
		return
	}
	log.Printf("节点 %s 故障: %s", old.Node.IP, reason)
	old.Node.Error = reason
	old.Node.FailedUntil = time.Now().Add(degradedBackoff).Unix()
	m.active = nil
	if m.standby != nil && m.standby.Alive() {
		sb := m.standby
		m.standby = nil
		m.setActive(sb, reason)
		log.Printf("已切换到备用节点 (无需重新握手)")
	} else {
		m.markDown(reason + "，且没有可用的备用节点")
	}
	m.release(old)
	m.RequestRefresh()
}

// release stops a tunnel in the background and returns its slot once routing is cleaned up.
func (m *Manager) release(t *Tunnel) {
	if m.active == t {
		m.active = nil
	}
	if m.standby == t {
		m.standby = nil
	}
	go func() {
		t.Stop()
		m.mu.Lock()
		m.slots = append(m.slots, t.Slot)
		m.mu.Unlock()
	}()
}

func (m *Manager) setStatus(s string) {
	m.mu.Lock()
	m.status = s
	m.mu.Unlock()
}

// ---------------------------------------------------------------- monitoring

// monitor watches active and standby in real time. Every MONITOR_INTERVAL both are probed in
// parallel; the active is switched to the standby as soon as its recent loss exceeds FAIL_LOSS_PCT
// while the standby is clean, or immediately when it stops answering.
func (m *Manager) monitor(ctx context.Context) {
	tick := time.NewTicker(m.cfg.MonitorInterval)
	defer tick.Stop()
	for i := 1; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		m.mu.RLock()
		tunnels := []*Tunnel{m.active, m.standby}
		m.mu.RUnlock()
		var wg sync.WaitGroup
		for _, t := range tunnels {
			if t != nil {
				wg.Add(1)
				go func(t *Tunnel) {
					defer wg.Done()
					m.observe(ctx, t)
				}(t)
			}
		}
		wg.Wait()
		m.decide()
		if i%15 == 0 {
			m.housekeeping()
		}
		if i%mtuRecheck == 0 {
			for _, t := range tunnels {
				if t != nil && t.Alive() {
					m.recheckMTU(ctx, t)
				}
			}
		}
	}
}

func (m *Manager) probe(ctx context.Context, t *Tunnel, count int) PingStats {
	m.mu.RLock()
	mode := t.Probe
	m.mu.RUnlock()
	if mode == "tcp" {
		return m.tcpProbe(ctx, t.Dev, count)
	}
	return Ping(ctx, m.cfg.ProbeTarget, count, monitorProbeSize, 100*time.Millisecond, time.Second, t.Dev)
}

// observe adds one monitoring round to the tunnel's live stats.
func (m *Manager) observe(ctx context.Context, t *Tunnel) {
	st := PingStats{Sent: probeCount}
	if t.Alive() {
		st = m.probe(ctx, t, probeCount)
	}
	if ctx.Err() != nil {
		return // interrupted by shutdown, not real loss
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	l := &t.Live
	l.Loss = append(l.Loss, st.LossPct())
	if len(l.Loss) > liveRounds {
		l.Loss = l.Loss[1:]
	}
	if avg := st.Avg(); avg != nil {
		if l.RTT == nil {
			l.RTT = avg
		} else {
			l.RTT = ptr(0.7**l.RTT + 0.3**avg)
		}
	}
}

// recheckMTU re-probes a running tunnel's path MTU in case the line changed (a few packets).
func (m *Manager) recheckMTU(ctx context.Context, t *Tunnel) {
	mtu := m.probeMTU(ctx, t)
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.Node.MTU != mtu {
		log.Printf("节点 %s 路径 MTU 变化: %d -> %d", t.Node.IP, t.Node.MTU, mtu)
		t.Node.MTU = mtu
	}
}

func dead(loss []float64) bool {
	n := len(loss)
	return n >= 3 && loss[n-1] >= 100 && loss[n-2] >= 100 && loss[n-3] >= 100
}

// decide applies the real-time switching rules (see monitor).
func (m *Manager) decide() {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, s := m.active, m.standby
	if a == nil {
		return
	}
	limit := m.cfg.FailLossPct
	if s != nil {
		sl := s.Live.Loss
		if !s.Alive() || dead(sl) || len(sl) >= minRounds && mean(sl) > limit {
			log.Printf("备用节点 %s 质量下降 (丢包 %.1f%%)，重新补充", s.Node.IP, meanOr(sl))
			s.Node.FailedUntil = time.Now().Add(degradedBackoff).Unix()
			m.release(s)
			m.RequestRefresh()
			s = nil
		}
	}
	al := a.Live.Loss
	switch {
	case !a.Alive():
		m.failover("OpenVPN 进程退出: " + tail(a.LastLog(), 80))
	case dead(al):
		m.failover("连续 3 轮检测无响应")
	case len(al) >= minRounds && mean(al) > limit && m.lockedID != a.Node.ID:
		if s != nil && len(s.Live.Loss) >= minRounds && mean(s.Live.Loss) < mean(al)/2 {
			m.failover(fmt.Sprintf("实时丢包 %.1f%%，切到备用 (丢包 %.1f%%)", mean(al), mean(s.Live.Loss)))
		} else if s == nil {
			m.RequestRefresh() // find a clean standby to switch to
		}
	}
}

// housekeeping refills a missing standby and moves back to a recovered pinned node.
func (m *Manager) housekeeping() {
	m.mu.RLock()
	pinned := m.nodes[m.lockedID]
	need := pinned != nil && m.active != nil && m.active.Node != pinned && !pinned.Failed(time.Now()) ||
		m.cfg.Standby && m.standby == nil
	m.mu.RUnlock()
	if need {
		m.RequestRefresh()
	}
}

func meanOr(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	return mean(xs)
}

// ---------------------------------------------------------------- snapshot & state

type TunnelView struct {
	Node
	Dev       string   `json:"dev"`
	Alive     bool     `json:"alive"`
	Since     int64    `json:"since"`
	Qualified bool     `json:"qualified"`
	LiveRTT   *float64 `json:"live_rtt"`  // smoothed, from the real-time monitor
	LiveLoss  *float64 `json:"live_loss"` // over the last ~30 s
}

type NodeView struct {
	Node
	Qualified bool   `json:"qualified"`
	Role      string `json:"role"`
}

func (m *Manager) Snapshot() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	minMbps := m.cfg.MinMbps
	view := func(t *Tunnel) *TunnelView {
		if t == nil {
			return nil
		}
		v := &TunnelView{Node: *t.Node, Dev: t.Dev, Alive: t.Alive(), Since: t.StartedAt.Unix(),
			Qualified: t.Node.Qualified(minMbps), LiveRTT: t.Live.RTT}
		if len(t.Live.Loss) > 0 {
			v.LiveLoss = ptr(mean(t.Live.Loss))
		}
		v.Config = ""
		return v
	}
	nodes := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	sort.SliceStable(nodes, func(i, j int) bool { return Better(nodes[i], nodes[j], minMbps) })
	list := make([]NodeView, 0, len(nodes))
	for _, n := range nodes {
		v := NodeView{Node: *n, Qualified: n.Qualified(minMbps)}
		v.Config = ""
		switch {
		case m.active != nil && m.active.Node == n:
			v.Role = "active"
		case m.standby != nil && m.standby.Node == n:
			v.Role = "standby"
		}
		list = append(list, v)
	}
	var nextReselect int64
	if m.active != nil && m.lockedID == "" {
		nextReselect = m.activeSince.Add(m.cfg.Hold).Unix()
	}
	return map[string]any{
		"status": m.status, "locked": m.lockedID != "", "locked_id": m.lockedID,
		"residential_only": m.cfg.ResidentialOnly, "min_mbps": minMbps,
		"hold_minutes": int(m.cfg.Hold.Minutes()), "next_reselect": nextReselect,
		"rotate_no_repeat": m.cfg.NoRepeat, "used_count": len(m.used),
		"last_refresh": m.lastRefresh,
		"active":       view(m.active), "standby": view(m.standby),
		"nodes": list,
	}
}

func (m *Manager) statePath() string { return filepath.Join(m.cfg.DataDir, "state.json") }

// saveState persists the pinned node and the active node (with its config) so a restart
// reconnects to the same exit IP. Caller holds m.mu.
func (m *Manager) saveState() {
	if m.closing {
		return
	}
	state := map[string]any{"locked_id": m.lockedID}
	if len(m.used) > 0 {
		used := make([]string, 0, len(m.used))
		for ip := range m.used {
			used = append(used, ip)
		}
		sort.Strings(used)
		state["used"] = used
	}
	if m.active != nil {
		state["last"] = m.active.Node
		state["active_since"] = m.activeSince.Unix()
		state["exit_ip"] = m.exitIP
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	tmp := m.statePath() + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, m.statePath())
	}
}

func describe(n *Node) string {
	speed := ""
	if n.ConnMs != nil {
		speed = fmt.Sprintf(" 真连接 %.0fms", *n.ConnMs)
	}
	if n.Mbps != nil {
		speed += fmt.Sprintf(" %.0fMbps", *n.Mbps)
	}
	isp := n.ISP
	if isp == "" {
		isp = "?"
	}
	return fmt.Sprintf("%s [%s %s %s] 延迟 %.0fms 抖动 %.1fms 丢包 %.0f%% MTU %d%s",
		n.IP, strings.ToUpper(n.Proto), n.Kind, isp, val(n.RTT), val(n.Jitter), val(n.Loss), n.MTU, speed)
}

func mean(xs []float64) float64 {
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}
