package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
