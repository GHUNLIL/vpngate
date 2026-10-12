package main

// Node selection, active/standby tunnels, health monitoring and failover.
//
// Pipeline: fetch list -> keep JP residential -> stage 1: direct RTT from the VPS (cheap, every node)
// -> stage 2: real tunnels for the top N, measuring RTT / jitter / loss / throughput through them
// -> best becomes active, runner-up stays connected as a warm standby for instant failover.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	failBackoff     = 30 * time.Minute // node failed to connect
	degradedBackoff = 10 * time.Minute // node connected but went bad
	healthWindow    = 12               // loss samples kept (~1 min at 5 s)
	speedtestURL    = "https://speed.cloudflare.com/__down?bytes=%d"
	exitInfoURL     = "http://ip-api.com/json/?fields=query"
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
	status      string
	liveRTT     *float64
	window      []float64
	lastRefresh int64
	slots       []int

	selectMu sync.Mutex // serialises selection / switching
	wake     chan struct{}
}

func NewManager(cfg *Config) *Manager {
	m := &Manager{cfg: cfg, res: NewResolver(cfg.DNSServers), nodes: map[string]*Node{},
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
		LockedID string `json:"locked_id"`
		Last     *Node  `json:"last"`
	}
	if data, err := os.ReadFile(m.statePath()); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	m.lockedID = state.LockedID
	if state.Last != nil && state.Last.Config != "" {
		m.nodes[state.Last.ID] = state.Last
		log.Printf("尝试恢复上次使用的节点 %s (保持出口 IP 不变)", state.Last.IP)
		if t := m.evaluate(ctx, state.Last, false); t != nil {
			m.mu.Lock()
			m.setActive(t)
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
		if err := m.refresh(ctx); err != nil {
			log.Printf("刷新节点列表失败: %v", err)
		}
		m.selectMu.Lock()
		m.ensure(ctx)
		m.selectMu.Unlock()

		interval := time.Minute
		if m.Route() != "" {
			interval = m.cfg.Refresh
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-time.After(interval):
		}
	}
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
		if t = m.evaluate(ctx, n, true); t == nil {
			m.mu.RLock()
			defer m.mu.RUnlock()
			return fmt.Errorf("连接失败: %s", n.Error)
		}
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
	ClassifyNodes(ctx, fresh, filepath.Join(m.cfg.DataDir, "ipinfo.json"))

	m.mu.Lock()
	merged := make(map[string]*Node, len(fresh))
	kinds := map[string]int{}
	for _, n := range fresh {
		kinds[n.Kind]++
		if old := m.nodes[n.ID]; old != nil { // keep measurements across refreshes
			n.HandshakeMs, n.RTT, n.Jitter, n.Loss, n.Mbps = old.HandshakeMs, old.RTT, old.Jitter, old.Loss, old.Mbps
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

// pool returns usable candidates (caller holds m.mu).
func (m *Manager) pool() []*Node {
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
	if !m.cfg.ResidentialOnly {
		return all
	}
	if len(home) == 0 && len(all) > 0 {
		log.Printf("没有可用的家宽节点，临时使用其他类型节点")
		return all
	}
	return home
}

func (m *Manager) inUse(n *Node) bool {
	return m.active != nil && m.active.Node == n || m.standby != nil && m.standby.Node == n
}

// prefilter is stage 1: direct RTT from the VPS to every candidate (TCP connect or ICMP).
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
			st := Ping(ctx, ip, 3, 100*time.Millisecond, time.Second, "")
			var best *float64
			for _, r := range st.RTTs {
				if best == nil || r < *best {
					best = ptr(r)
				}
			}
			results[i] = result{best, true} // many home routers drop ICMP: keep UDP nodes anyway
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
	upgrade := m.cfg.AutoUpgrade && m.lockedID == "" && !needActive
	m.mu.RUnlock()
	if !needActive && !needStandby && !upgrade {
		return
	}
	m.setStatus("正在测试节点")
	tunnels := m.acquire(ctx)
	if upgrade && len(tunnels) > 0 {
		m.mu.RLock()
		cur := m.active
		m.mu.RUnlock()
		if cur != nil && m.measure(ctx, cur, false) == nil {
			m.mu.Lock()
			now, best := cur.Node.Score(m.cfg.TCPPenaltyMs), tunnels[0].Node.Score(m.cfg.TCPPenaltyMs)
			if m.active == cur && best < now*0.8 && now-best > 10 {
				m.promote(tunnels[0], fmt.Sprintf("发现更优节点 (评分 %.0f → %.0f)", now, best))
				tunnels = tunnels[1:]
			}
			m.mu.Unlock()
		}
	}
	m.mu.Lock()
	if (m.active == nil || !m.active.Alive()) && len(tunnels) > 0 {
		if m.active != nil {
			m.release(m.active)
		}
		m.setActive(tunnels[0])
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
	}
	m.mu.Unlock()
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
		t = m.evaluate(ctx, n, false)
	}
	if t != nil {
		m.mu.Lock()
		m.promote(t, "恢复锁定节点")
		m.mu.Unlock()
	}
}

// acquire is stage 2: deep-test the top candidates in parallel; returns working tunnels, best first.
func (m *Manager) acquire(ctx context.Context) []*Tunnel {
	pen := m.cfg.TCPPenaltyMs
	m.mu.RLock()
	cands := m.pool()
	sort.Slice(cands, func(i, j int) bool { return cands[i].PrefilterKey(pen) < cands[j].PrefilterKey(pen) })
	m.mu.RUnlock()
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
			results[i] = m.evaluate(ctx, n, true)
		}(i, n)
	}
	wg.Wait()
	var tunnels []*Tunnel
	for _, t := range results {
		if t != nil {
			tunnels = append(tunnels, t)
		}
	}
	m.mu.RLock()
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Node.Score(pen) < tunnels[j].Node.Score(pen) })
	for _, t := range tunnels {
		log.Printf("  %s", describe(t.Node))
	}
	m.mu.RUnlock()
	return tunnels
}

func (m *Manager) evaluate(ctx context.Context, n *Node, speedtest bool) *Tunnel {
	m.mu.Lock()
	if len(m.slots) == 0 {
		m.mu.Unlock()
		return nil
	}
	slot := m.slots[0]
	m.slots = m.slots[1:]
	m.mu.Unlock()

	t := NewTunnel(n, slot, m.cfg.RunDir())
	hs, err := t.Start(ctx, m.cfg.OpenVPN, m.auth, m.version, 25*time.Second)
	if err == nil {
		m.mu.Lock()
		n.HandshakeMs = ptr(hs)
		m.mu.Unlock()
		err = m.measure(ctx, t, speedtest)
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

func (m *Manager) measure(ctx context.Context, t *Tunnel, speedtest bool) error {
	st := Ping(ctx, m.cfg.ProbeTarget, 10, 100*time.Millisecond, time.Second, t.Dev)
	probe := "icmp"
	if len(st.RTTs) == 0 { // some nodes drop ICMP: fall back to TCP handshakes
		st, probe = m.tcpProbe(ctx, t.Dev, 3), "tcp"
	}
	if len(st.RTTs) == 0 {
		return fmt.Errorf("隧道已建立但无法访问外网")
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
	var mbps *float64
	if speedtest && m.cfg.SpeedtestBytes > 0 {
		if v, err := SpeedTest(ctx, m.res, fmt.Sprintf(speedtestURL, m.cfg.SpeedtestBytes), t.Dev); err == nil {
			mbps = ptr(v)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := t.Node
	t.Probe = probe
	n.RTT, n.Jitter, n.Loss = st.Avg(), ptr(st.Jitter()), ptr(st.LossPct())
	n.TestedAt = time.Now().Unix()
	if exitIP != "" {
		n.ExitIP = exitIP
	}
	if mbps != nil {
		n.Mbps = mbps
	}
	return nil
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

func (m *Manager) setActive(t *Tunnel) {
	m.active = t
	m.window = m.window[:0]
	m.liveRTT = t.Node.RTT
	log.Printf("当前节点: %s", describe(t.Node))
	m.saveState()
}

// promote is make-before-break: the old active becomes the standby so open connections survive.
func (m *Manager) promote(t *Tunnel, reason string) {
	old := m.active
	m.setActive(t)
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
		m.setActive(sb)
		log.Printf("已切换到备用节点 (无需重新握手)")
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

func (m *Manager) monitor(ctx context.Context) {
	tick := time.NewTicker(m.cfg.MonitorInterval)
	defer tick.Stop()
	for i := 1; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		m.checkActive(ctx)
		if i%6 == 0 {
			m.checkStandby(ctx)
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
	return Ping(ctx, m.cfg.ProbeTarget, count, 200*time.Millisecond, time.Second, t.Dev)
}

func (m *Manager) checkActive(ctx context.Context) {
	m.mu.RLock()
	t := m.active
	m.mu.RUnlock()
	if t == nil {
		return
	}
	if !t.Alive() {
		m.mu.Lock()
		if m.active == t {
			m.failover("OpenVPN 进程退出: " + tail(t.LastLog(), 80))
		}
		m.mu.Unlock()
		return
	}
	st := m.probe(ctx, t, 3)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != t {
		return
	}
	m.window = append(m.window, st.LossPct())
	if len(m.window) > healthWindow {
		m.window = m.window[1:]
	}
	if avg := st.Avg(); avg != nil {
		if m.liveRTT == nil {
			m.liveRTT = avg
		} else {
			m.liveRTT = ptr(0.8**m.liveRTT + 0.2**avg)
		}
	}
	w := m.window
	if len(w) >= 3 && w[len(w)-1] >= 100 && w[len(w)-2] >= 100 && w[len(w)-3] >= 100 {
		m.failover("连续 3 次检测无响应")
	} else if len(w) == healthWindow && mean(w) > m.cfg.FailLossPct {
		m.failover(fmt.Sprintf("持续丢包 %.0f%%", mean(w)))
	}
}

func (m *Manager) checkStandby(ctx context.Context) {
	m.mu.RLock()
	t := m.standby
	pinned := m.nodes[m.lockedID]
	backToPinned := pinned != nil && m.active != nil && m.active.Node != pinned && !pinned.Failed(time.Now())
	m.mu.RUnlock()
	if backToPinned {
		m.RequestRefresh()
	}
	if t == nil {
		if m.cfg.Standby {
			m.RequestRefresh()
		}
		return
	}
	if t.Alive() && len(m.probe(ctx, t, 3).RTTs) > 0 {
		return
	}
	m.mu.Lock()
	if m.standby == t {
		log.Printf("备用节点 %s 失效，重新补充", t.Node.IP)
		t.Node.FailedUntil = time.Now().Add(degradedBackoff).Unix()
		m.release(t)
	}
	m.mu.Unlock()
	m.RequestRefresh()
}

// ---------------------------------------------------------------- snapshot & state

type TunnelView struct {
	Node
	Dev   string   `json:"dev"`
	Alive bool     `json:"alive"`
	Since int64    `json:"since"`
	Score *float64 `json:"score"`
}

type NodeView struct {
	Node
	Score *float64 `json:"score"`
	Role  string   `json:"role"`
}

func (m *Manager) Snapshot() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pen := m.cfg.TCPPenaltyMs
	score := func(n *Node) *float64 {
		if s := n.Score(pen); s < 1e18 {
			return ptr(float64(int(s*10)) / 10)
		}
		return nil
	}
	view := func(t *Tunnel) *TunnelView {
		if t == nil {
			return nil
		}
		v := &TunnelView{Node: *t.Node, Dev: t.Dev, Alive: t.Alive(), Since: t.StartedAt.Unix(), Score: score(t.Node)}
		v.Config = ""
		return v
	}
	nodes := make([]*Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		si, sj := nodes[i].Score(pen), nodes[j].Score(pen)
		if si != sj {
			return si < sj
		}
		return nodes[i].PrefilterKey(pen) < nodes[j].PrefilterKey(pen)
	})
	list := make([]NodeView, 0, len(nodes))
	for _, n := range nodes {
		v := NodeView{Node: *n, Score: score(n)}
		v.Config = ""
		switch {
		case m.active != nil && m.active.Node == n:
			v.Role = "active"
		case m.standby != nil && m.standby.Node == n:
			v.Role = "standby"
		}
		list = append(list, v)
	}
	var loss *float64
	if len(m.window) > 0 {
		loss = ptr(mean(m.window))
	}
	return map[string]any{
		"status": m.status, "locked": m.lockedID != "", "locked_id": m.lockedID,
		"auto_upgrade": m.cfg.AutoUpgrade, "residential_only": m.cfg.ResidentialOnly,
		"last_refresh": m.lastRefresh,
		"active":       view(m.active), "standby": view(m.standby),
		"live":  map[string]*float64{"rtt": m.liveRTT, "loss": loss},
		"nodes": list,
	}
}

func (m *Manager) statePath() string { return filepath.Join(m.cfg.DataDir, "state.json") }

// saveState persists the pinned node and the active node (with its config) so a restart
// reconnects to the same exit IP. Caller holds m.mu.
func (m *Manager) saveState() {
	state := map[string]any{"locked_id": m.lockedID}
	if m.active != nil {
		state["last"] = m.active.Node
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
	if n.Mbps != nil {
		speed = fmt.Sprintf(" %.0fMbps", *n.Mbps)
	}
	isp := n.ISP
	if isp == "" {
		isp = "?"
	}
	return fmt.Sprintf("%s [%s %s %s] 延迟 %.0fms 抖动 %.1fms 丢包 %.0f%%%s",
		n.IP, strings.ToUpper(n.Proto), n.Kind, isp, val(n.RTT), val(n.Jitter), val(n.Loss), speed)
}

func mean(xs []float64) float64 {
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}
