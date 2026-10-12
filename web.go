package main

// Admin web UI and JSON API: HTTP Basic auth, brute-force lockout, CSRF header on writes.

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

const (
	maxAuthFailures = 10
	lockoutPeriod   = 10 * time.Minute
)

type WebUI struct {
	cfg     *Config
	manager *Manager
	ss      *SSServer
	logs    *LogRing

	mu       sync.Mutex
	failures map[string]failure
}

type failure struct {
	count int
	first time.Time
}

func NewWebUI(cfg *Config, m *Manager, ss *SSServer, logs *LogRing) *WebUI {
	return &WebUI{cfg: cfg, manager: m, ss: ss, logs: logs, failures: map[string]failure{}}
}

func (w *WebUI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = rw.Write(uiHTML)
	})
	mux.HandleFunc("GET /api/status", func(rw http.ResponseWriter, _ *http.Request) {
		writeJSON(rw, http.StatusOK, w.status())
	})
	mux.HandleFunc("POST /api/switch", w.action(func(r *http.Request, body map[string]any) error {
		id, _ := body["id"].(string)
		return w.manager.SwitchTo(r.Context(), id)
	}))
	mux.HandleFunc("POST /api/refresh", w.action(func(*http.Request, map[string]any) error {
		w.manager.RequestRefresh()
		return nil
	}))
	mux.HandleFunc("POST /api/lock", w.action(func(_ *http.Request, body map[string]any) error {
		locked, _ := body["locked"].(bool)
		w.manager.SetLocked(locked)
		return nil
	}))
	return w.guard(mux)
}

func (w *WebUI) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: w.Handler(), ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (w *WebUI) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")

		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		if w.lockedOut(peer) {
			http.Error(rw, "登录失败次数过多，请 10 分钟后再试", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			h.Set("WWW-Authenticate", `Basic realm="VPNGATE"`)
			http.Error(rw, "authentication required", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(user), []byte(w.cfg.WebUser))&
			subtle.ConstantTimeCompare([]byte(pass), []byte(w.cfg.WebPass)) != 1 {
			w.recordFailure(peer)
			h.Set("WWW-Authenticate", `Basic realm="VPNGATE"`)
			http.Error(rw, "authentication required", http.StatusUnauthorized)
			return
		}
		w.mu.Lock()
		delete(w.failures, peer)
		w.mu.Unlock()
		if r.Method == http.MethodPost && r.Header.Get("X-Requested-With") != "vpngate" {
			http.Error(rw, "forbidden", http.StatusForbidden) // blocks cross-site form posts
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *WebUI) lockedOut(peer string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	f, ok := w.failures[peer]
	if ok && time.Since(f.first) > lockoutPeriod {
		delete(w.failures, peer)
		return false
	}
	return f.count >= maxAuthFailures
}

func (w *WebUI) recordFailure(peer string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f, ok := w.failures[peer]
	if !ok {
		f.first = time.Now()
	}
	f.count++
	w.failures[peer] = f
}

func (w *WebUI) action(fn func(*http.Request, map[string]any) error) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		body := map[string]any{}
		_ = json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&body)
		if err := fn(r, body); err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true})
	}
}

func (w *WebUI) status() map[string]any {
	s := w.manager.Snapshot()
	s["version"] = version
	s["ss"] = map[string]any{"port": w.cfg.SSPort, "method": w.cfg.SSMethod, "password": w.cfg.SSPassword,
		"active": w.ss.Active.Load()}
	s["logs"] = w.logs.Lines()
	return s
}

func writeJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}
