package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- web

func newWeb(t *testing.T) (*WebUI, *Manager) {
	t.Setenv("WEB_PASS", "test")
	t.Setenv("SS_PASSWORD", "sspw")
	t.Setenv("DATA_DIR", t.TempDir())
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(cfg)
	m.nodes = map[string]*Node{
		"a": {ID: "a", IP: "1.2.3.4", Proto: "udp", Kind: "residential", RTT: ptr(20), Config: "secret"},
		"b": {ID: "b", IP: "5.6.7.8", Proto: "tcp", Kind: "hosting"},
	}
	return NewWebUI(cfg, m, &SSServer{}, &LogRing{}), m
}

func call(h http.Handler, method, path, user, pass string, csrf bool, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "1.1.1.1:1234"
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	if csrf {
		req.Header.Set("X-Requested-With", "vpngate")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWebAuthAndStatus(t *testing.T) {
	w, _ := newWeb(t)
	h := w.Handler()
	if rec := call(h, "GET", "/", "", "", false, ""); rec.Code != 401 {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	rec := call(h, "GET", "/api/status", "admin", "test", false, "")
	var data struct {
		Nodes []map[string]any `json:"nodes"`
		SS    map[string]any   `json:"ss"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil || rec.Code != 200 {
		t.Fatalf("status %d %v", rec.Code, err)
	}
	if data.Nodes[0]["id"] != "a" || data.SS["port"] != float64(7929) || strings.Contains(rec.Body.String(), "secret") {
		t.Errorf("bad status payload %s", rec.Body.String())
	}
	if rec := call(h, "GET", "/", "admin", "test", false, ""); !strings.Contains(rec.Body.String(), "VPNGATE") {
		t.Error("UI not served")
	}
}

func TestWebLockoutAndCSRF(t *testing.T) {
	w, _ := newWeb(t)
	h := w.Handler()
	if rec := call(h, "POST", "/api/refresh", "admin", "test", false, "{}"); rec.Code != 403 {
		t.Errorf("POST without CSRF header: %d", rec.Code)
	}
	if rec := call(h, "POST", "/api/refresh", "admin", "test", true, "{}"); rec.Code != 200 {
		t.Errorf("refresh: %d", rec.Code)
	}
	if rec := call(h, "POST", "/api/switch", "admin", "test", true, `{"id":"zz"}`); rec.Code != 400 {
		t.Errorf("switch to unknown node: %d", rec.Code)
	}
	for i := 0; i < maxAuthFailures; i++ {
		call(h, "GET", "/", "admin", "wrong", false, "")
	}
	if rec := call(h, "GET", "/", "admin", "test", false, ""); rec.Code != 429 {
		t.Errorf("want lockout 429, got %d", rec.Code)
	}
}

func TestPoolTransport(t *testing.T) {
	_, m := newWeb(t)
	m.nodes["c"] = &Node{ID: "c", IP: "9.9.9.9", Proto: "tcp", Kind: "residential"}
	pool := m.pool()
	if len(pool) != 1 || pool[0].ID != "a" {
		t.Errorf("TRANSPORT=udp must keep only UDP nodes, got %d", len(pool))
	}
	m.nodes["a"].FailedUntil = time.Now().Add(time.Hour).Unix()
	if pool := m.pool(); len(pool) != 1 || pool[0].ID != "c" {
		t.Error("with no UDP node left, TCP is the fallback")
	}
	m.cfg.Transport = "auto"
	m.nodes["a"].FailedUntil = 0
	if len(m.pool()) != 2 {
		t.Error("auto takes both")
	}
}

func TestPoolResidentialFallback(t *testing.T) {
	_, m := newWeb(t)
	m.cfg.Transport = "auto"
	if pool := m.pool(); len(pool) != 1 || pool[0].ID != "a" {
		t.Errorf("want only residential node, got %d", len(pool))
	}
	m.nodes["a"].Kind = "hosting"
	if pool := m.pool(); len(pool) != 2 {
		t.Errorf("want fallback to all nodes, got %d", len(pool))
	}
}

func TestRotationNoRepeat(t *testing.T) {
	t.Setenv("ROTATE_NO_REPEAT", "1")
	t.Setenv("HOLD_MINUTES", "2")
	_, m := newWeb(t)
	if !m.cfg.NoRepeat || m.cfg.Hold != 2*time.Minute {
		t.Fatalf("config: no_repeat=%v hold=%v", m.cfg.NoRepeat, m.cfg.Hold)
	}
	m.nodes["c"] = &Node{ID: "c", IP: "9.9.9.9", Proto: "udp", Kind: "residential", ExitIP: "9.9.9.10"}
	tun := func(id string) *Tunnel { return &Tunnel{Node: m.nodes[id], exited: make(chan struct{})} }

	m.mu.Lock()
	defer m.mu.Unlock()
	m.setActive(tun("a"), "start")
	if pool := m.pool(); len(pool) != 1 || pool[0].ID != "c" {
		t.Fatalf("after using a, only c may be picked, got %d", len(pool))
	}
	m.setActive(tun("c"), "rotate")
	if len(m.pool()) != 0 {
		t.Fatal("a is used and c is active: nothing left this round")
	}
	if !m.used["9.9.9.10"] {
		t.Error("the exit IP must be recorded too")
	}
	m.resetUsed()
	if pool := m.pool(); len(pool) != 1 || pool[0].ID != "a" {
		t.Errorf("after reset a is available again, got %d", len(pool))
	}
	if !m.isUsed(m.nodes["c"]) {
		t.Error("the current exit IP stays recorded after a reset")
	}
	data, _ := os.ReadFile(m.statePath())
	if !strings.Contains(string(data), `"used":["9.9.9.10","9.9.9.9"]`) {
		t.Errorf("used IPs must survive a restart, state: %s", data)
	}
}

func TestConnectTestRanking(t *testing.T) {
	// a pings faster, but b answers real requests faster: with a connect test b wins
	a := &Node{RTT: ptr(20.0), Loss: ptr(0.0), ConnMs: ptr(400.0)}
	b := &Node{RTT: ptr(30.0), Loss: ptr(0.0), ConnMs: ptr(150.0)}
	if !Better(b, a, 0) || Better(a, b, 0) {
		t.Error("connect-test time must decide between qualified nodes")
	}
	a.ConnMs, b.ConnMs = nil, nil
	if !Better(a, b, 0) {
		t.Error("without a connect test ping RTT decides")
	}
	b.ConnMs, b.Loss = ptr(100.0), ptr(33.3) // one of three real requests failed
	if !Better(a, b, 0) {
		t.Error("failed real requests count as loss and disqualify")
	}
}

func TestWebAllowList(t *testing.T) {
	t.Setenv("WEB_ALLOW", "203.0.113.0/24")
	w, _ := newWeb(t)
	h := w.Handler()
	if rec := call(h, "GET", "/", "admin", "test", false, ""); rec.Code != 403 {
		t.Errorf("source outside WEB_ALLOW: want 403, got %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.SetBasicAuth("admin", "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("allowed source: want 200, got %d", rec.Code)
	}
}

func TestExitIPNotifications(t *testing.T) {
	got := make(chan Event, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var e Event
		_ = json.NewDecoder(r.Body).Decode(&e)
		got <- e
	}))
	defer hook.Close()
	t.Setenv("NOTIFY_WEBHOOK", hook.URL)
	_, m := newWeb(t)
	tun := func(ip string) *Tunnel {
		return &Tunnel{Node: &Node{ID: ip, IP: ip, ExitIP: ip, ISP: "ISP", Proto: "udp"}, exited: make(chan struct{})}
	}
	next := func() Event {
		select {
		case e := <-got:
			return e
		case <-time.After(3 * time.Second):
			t.Fatal("no notification")
			return Event{}
		}
	}
	m.mu.Lock()
	m.setActive(tun("1.1.1.1"), "start") // first IP: nothing to announce
	m.standby = tun("2.2.2.2")
	m.failover("丢包")
	m.mu.Unlock()
	if e := next(); e.Event != "exit_ip_changed" || e.OldIP != "1.1.1.1" || e.NewIP != "2.2.2.2" || e.Reason != "丢包" {
		t.Errorf("change event %+v", e)
	}
	m.mu.Lock()
	m.failover("断线") // no standby left -> outage
	m.setActive(tun("3.3.3.3"), "选出新节点")
	m.mu.Unlock()
	if e := next(); e.Event != "no_node" {
		t.Errorf("want outage event, got %+v", e)
	}
	if e := next(); e.Event != "recovered" || e.NewIP != "3.3.3.3" {
		t.Errorf("want recovery event, got %+v", e)
	}
}
