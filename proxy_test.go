package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type proxyRig struct {
	p       *Proxy
	mu      sync.Mutex
	targets []string
}

func newRig(t *testing.T, user, pass string, allow []*net.IPNet) *proxyRig {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	r := &proxyRig{}
	r.p = &Proxy{Addr: "127.0.0.1:0", User: user, Pass: pass, Allow: allow, MaxConns: 100,
		Dial: func(ctx context.Context, host string, port int) (net.Conn, error) {
			r.mu.Lock()
			r.targets = append(r.targets, net.JoinHostPort(host, strconv.Itoa(port)))
			r.mu.Unlock()
			if host == "blocked.test" {
				return nil, errBlocked
			}
			return net.Dial("tcp", echo.Addr().String())
		}}
	if err := r.p.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.p.Serve() }()
	t.Cleanup(func() { r.p.Close(); echo.Close() })
	return r
}

func (r *proxyRig) dial(t *testing.T) net.Conn {
	c, err := net.Dial("tcp", r.p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSOCKS5NoAuthDomain(t *testing.T) {
	r := newRig(t, "", "", nil)
	c := r.dial(t)
	c.Write([]byte{5, 1, 0})
	if b := readN(t, c, 2); b[1] != 0 {
		t.Fatalf("method reply %v", b)
	}
	c.Write(append([]byte("\x05\x01\x00\x03\x0bexample.com\x01\xbb"), "hello"...))
	if b := readN(t, c, 10); b[1] != 0 {
		t.Fatalf("connect reply %v", b)
	}
	if string(readN(t, c, 5)) != "hello" {
		t.Fatal("pipelined data not relayed")
	}
	c.Write([]byte(" world"))
	if string(readN(t, c, 6)) != " world" {
		t.Fatal("relay broken")
	}
	if r.targets[0] != "example.com:443" {
		t.Errorf("target %v", r.targets)
	}
}

func TestSOCKS5Auth(t *testing.T) {
	r := newRig(t, "u", "p", nil)
	c := r.dial(t)
	c.Write([]byte("\x05\x01\x02\x01\x01u\x01x"))
	if b := readN(t, c, 4); string(b) != "\x05\x02\x01\x01" {
		t.Fatalf("bad password accepted: %v", b)
	}
	c = r.dial(t)
	c.Write([]byte("\x05\x01\x02\x01\x01u\x01p\x05\x01\x00\x01\x01\x02\x03\x04\x00\x50"))
	if b := readN(t, c, 4); string(b) != "\x05\x02\x01\x00" {
		t.Fatalf("auth failed: %v", b)
	}
	if b := readN(t, c, 10); b[1] != 0 {
		t.Fatalf("connect reply %v", b)
	}
	if r.targets[0] != "1.2.3.4:80" {
		t.Errorf("target %v", r.targets)
	}
}

func TestSOCKS5Errors(t *testing.T) {
	r := newRig(t, "", "", nil)
	c := r.dial(t)
	c.Write([]byte("\x05\x01\x00\x05\x03\x00\x01\x01\x02\x03\x04\x00\x50")) // UDP ASSOCIATE
	readN(t, c, 2)
	if b := readN(t, c, 4); b[1] != 7 {
		t.Errorf("want command-not-supported, got %v", b)
	}
	c = r.dial(t)
	c.Write([]byte("\x05\x01\x00\x05\x01\x00\x03\x0cblocked.test\x00\x50"))
	readN(t, c, 2)
	if b := readN(t, c, 4); b[1] != 2 {
		t.Errorf("want not-allowed, got %v", b)
	}
}

func TestFastConnectRepliesBeforeUpstream(t *testing.T) {
	r := newRig(t, "", "", nil)
	r.p.FastConnect = true
	inner := r.p.Dial
	r.p.Dial = func(ctx context.Context, host string, port int) (net.Conn, error) {
		time.Sleep(300 * time.Millisecond) // slow tunnel connect
		return inner(ctx, host, port)
	}
	c := r.dial(t)
	start := time.Now()
	c.Write([]byte("\x05\x01\x00\x05\x01\x00\x03\x04a.jp\x01\xbbhello"))
	readN(t, c, 2)
	if b := readN(t, c, 10); b[1] != 0 || time.Since(start) > 150*time.Millisecond {
		t.Fatalf("reply %v after %v, want immediate success", b, time.Since(start))
	}
	if string(readN(t, c, 5)) != "hello" {
		t.Fatal("data sent before upstream was ready got lost")
	}
	// A failed upstream after the optimistic reply must close the client connection.
	c = r.dial(t)
	c.Write([]byte("CONNECT blocked.test:443 HTTP/1.1\r\n\r\n"))
	br := bufio.NewReader(c)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("want optimistic 200, got %q", line)
	}
	br.ReadString('\n')
	if _, err := br.ReadByte(); err == nil {
		t.Error("connection should be closed when upstream fails")
	}
}

func TestHTTPConnectAuth(t *testing.T) {
	r := newRig(t, "u", "p", nil)
	c := r.dial(t)
	c.Write([]byte("CONNECT a.jp:443 HTTP/1.1\r\nHost: a.jp:443\r\n\r\n"))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "407") {
		t.Fatalf("want 407, got %q", line)
	}
	c = r.dial(t)
	token := base64.StdEncoding.EncodeToString([]byte("u:p"))
	c.Write([]byte("CONNECT a.jp:8443 HTTP/1.1\r\nProxy-Authorization: Basic " + token + "\r\n\r\nearly"))
	br := bufio.NewReader(c)
	line, _ = br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("want 200, got %q", line)
	}
	br.ReadString('\n')
	b := make([]byte, 5)
	io.ReadFull(br, b)
	if string(b) != "early" || r.targets[0] != "a.jp:8443" {
		t.Errorf("got %q targets %v", b, r.targets)
	}
}

func TestHTTPForwardRewrite(t *testing.T) {
	r := newRig(t, "", "", nil)
	c := r.dial(t)
	c.Write([]byte("GET http://a.jp/x?y=1 HTTP/1.1\r\nHost: a.jp\r\nProxy-Connection: keep-alive\r\n\r\n"))
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	got := head.String()
	if !strings.HasPrefix(got, "GET /x?y=1 HTTP/1.1\r\n") || strings.Contains(got, "Proxy-Connection") ||
		!strings.Contains(got, "Connection: close") || r.targets[0] != "a.jp:80" {
		t.Errorf("bad rewrite %q", got)
	}
}

func TestAllowlist(t *testing.T) {
	_, n, _ := net.ParseCIDR("203.0.113.0/24")
	p := &Proxy{Allow: []*net.IPNet{n}}
	for ip, want := range map[string]bool{"127.0.0.1": true, "203.0.113.9": true, "198.51.100.1": false} {
		if got := p.allowed(&net.TCPAddr{IP: net.ParseIP(ip)}); got != want {
			t.Errorf("%s: got %v", ip, got)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	for in, want := range map[string]string{"a.jp:8443": "a.jp 8443", "a.jp": "a.jp 443", "[2001:db8::1]:8080": "2001:db8::1 8080"} {
		h, p := splitHostPort(in, 443)
		if h+" "+strconv.Itoa(p) != want {
			t.Errorf("%s -> %s %d", in, h, p)
		}
	}
}

// ---------------------------------------------------------------- web

func newWeb(t *testing.T) (*WebUI, *Manager) {
	t.Setenv("WEB_PASS", "test")
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
	return NewWebUI(cfg, m, &Proxy{User: "pu", Pass: "pp"}, nil, &LogRing{}), m
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
		Proxy map[string]any   `json:"proxy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil || rec.Code != 200 {
		t.Fatalf("status %d %v", rec.Code, err)
	}
	if data.Nodes[0]["id"] != "a" || data.Proxy["user"] != "pu" || strings.Contains(rec.Body.String(), "secret") {
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

func TestPoolResidentialFallback(t *testing.T) {
	_, m := newWeb(t)
	if pool := m.pool(); len(pool) != 1 || pool[0].ID != "a" {
		t.Errorf("want only residential node, got %d", len(pool))
	}
	m.nodes["a"].Kind = "hosting"
	if pool := m.pool(); len(pool) != 2 {
		t.Errorf("want fallback to all nodes, got %d", len(pool))
	}
}

// ---------------------------------------------------------------- shadowsocks

func newSSRig(t *testing.T) (*SSServer, *ssCipher, *proxyRig) {
	rig := newRig(t, "", "", nil) // reuse the echo target + recording dialer
	c, err := newSSCipher("aes-128-gcm", "secret")
	if err != nil {
		t.Fatal(err)
	}
	s := &SSServer{Addr: "127.0.0.1:0", Cipher: c, Allow: func(net.IP) bool { return true },
		Dial: rig.p.Dial, Res: NewResolver(nil), Route: func() string { return "test0" }, allowPrivate: true,
		listenUDP: func(string) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") }}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(s.Close)
	return s, c, rig
}

func TestShadowsocksTCP(t *testing.T) {
	s, c, rig := newSSRig(t)
	conn, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	w, _ := newSSWriter(conn, c)
	w.Write(append([]byte("\x03\x0bexample.com\x01\xbb"), "hello over ss"...))
	salt := make([]byte, c.saltSize())
	if _, err := io.ReadFull(conn, salt); err != nil {
		t.Fatal(err)
	}
	aead, _ := c.aead(salt)
	got := make([]byte, 13)
	if _, err := io.ReadFull(newSSReader(conn, aead), got); err != nil || string(got) != "hello over ss" {
		t.Fatalf("echo %q %v", got, err)
	}
	if rig.targets[0] != "example.com:443" {
		t.Errorf("target %v", rig.targets)
	}
}

func TestShadowsocksRejectsWrongPasswordAndReplay(t *testing.T) {
	s, c, _ := newSSRig(t)
	send := func(payload []byte) net.Conn {
		conn, err := net.Dial("tcp", s.ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		conn.Write(payload)
		return conn
	}
	bad, _ := newSSCipher("aes-128-gcm", "wrong")
	var buf strings.Builder
	w, _ := newSSWriter(&buf, bad)
	w.Write([]byte("\x01\x01\x02\x03\x04\x00\x50"))
	conn := send([]byte(buf.String()))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("wrong password must get no reply")
	}
	buf.Reset()
	w, _ = newSSWriter(&buf, c)
	w.Write([]byte("\x01\x01\x02\x03\x04\x00\x50ping"))
	first := send([]byte(buf.String()))
	if _, err := first.Read(make([]byte, 1)); err != nil {
		t.Fatalf("valid handshake failed: %v", err)
	}
	replay := send([]byte(buf.String()))
	if _, err := replay.Read(make([]byte, 1)); err == nil {
		t.Error("replayed handshake must be ignored")
	}
}

func TestShadowsocksUDP(t *testing.T) {
	s, c, _ := newSSRig(t)
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	client, err := net.DialUDP("udp4", nil, s.pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := socksAddrBytes(echo.LocalAddr().(*net.UDPAddr).AddrPort())
	salt := make([]byte, c.saltSize())
	rand.Read(salt)
	aead, _ := c.aead(salt)
	client.Write(aead.Seal(salt, make([]byte, 12), append(target, "dns?"...), nil))

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	aead, _ = c.aead(buf[:c.saltSize()])
	plain, err := aead.Open(nil, make([]byte, 12), buf[c.saltSize():n], nil)
	if err != nil {
		t.Fatal(err)
	}
	_, port, hl, err := parseSocksAddr(plain)
	if err != nil || port != echo.LocalAddr().(*net.UDPAddr).Port || string(plain[hl:]) != "re:dns?" {
		t.Fatalf("reply %q port %d err %v", plain, port, err)
	}
}

func TestSSURI(t *testing.T) {
	if got := SSURI("aes-128-gcm", "pw", "1.2.3.4", 7929, "VPNGATE"); got != "ss://YWVzLTEyOC1nY206cHc@1.2.3.4:7929#VPNGATE" {
		t.Errorf("got %s", got)
	}
}
