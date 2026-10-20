package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// ---------------------------------------------------------------- SOCKS5 exits

func newSocksRig(t *testing.T, dial Dial) *SocksServer {
	s := &SocksServer{Addr: "127.0.0.1:0", User: "u", Pass: "p", Allow: func(net.IP) bool { return true }, Dial: dial}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(s.Close)
	return s
}

func echoDial(t *testing.T) (Dial, chan string) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	target := make(chan string, 8)
	return func(_ context.Context, host string, port int) (net.Conn, error) {
		target <- net.JoinHostPort(host, strconv.Itoa(port))
		return net.Dial("tcp", echo.Addr().String())
	}, target
}

// socksHandshake performs greeting, auth and CONNECT example.com:443; returns the reply code.
func socksHandshake(t *testing.T, addr, user, pass string) (net.Conn, byte) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 2})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte{5, 2} {
		t.Fatalf("method reply %v %v", m, err)
	}
	c.Write(append(append(append([]byte{1, byte(len(user))}, user...), byte(len(pass))), pass...))
	var a [2]byte
	if _, err := io.ReadFull(c, a[:]); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if a[1] != 0 {
		return c, 0xff
	}
	c.Write(append([]byte{5, 1, 0, 3, 11}, "example.com\x01\xbb"...))
	var r [10]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return c, r[1]
}

func TestSocksConnect(t *testing.T) {
	dial, target := echoDial(t)
	s := newSocksRig(t, dial)
	c, code := socksHandshake(t, s.ln.Addr().String(), "u", "p")
	if code != 0 {
		t.Fatalf("reply %d", code)
	}
	c.Write([]byte("hello"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo %q %v", got, err)
	}
	if got := <-target; got != "example.com:443" {
		t.Errorf("target %s", got)
	}
}

func TestSocksRejectsWrongPassword(t *testing.T) {
	dial, _ := echoDial(t)
	s := newSocksRig(t, dial)
	if _, code := socksHandshake(t, s.ln.Addr().String(), "u", "wrong"); code != 0xff {
		t.Fatal("wrong password accepted")
	}
}

func TestSocksRequiresAuthMethod(t *testing.T) {
	dial, _ := echoDial(t)
	s := newSocksRig(t, dial)
	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0}) // offers "no auth" only
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 0xff {
		t.Fatalf("got %v %v", m, err)
	}
}

func TestSocksNoTunnelFails(t *testing.T) {
	s := newSocksRig(t, TunnelDialer(NewResolver(nil), func() string { return "" }))
	if _, code := socksHandshake(t, s.ln.Addr().String(), "u", "p"); code != 1 {
		t.Fatalf("reply %d, want general failure", code)
	}
}

// ---------------------------------------------------------------- exit pool

func TestExitPoolKeepsIPsDistinct(t *testing.T) {
	t.Setenv("WEB_PASS", "test")
	t.Setenv("SS_PASSWORD", "sspw")
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("EXITS", "2")
	t.Setenv("EXIT_PASS", "pw")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(cfg)
	a := &Node{ID: "a", IP: "1.1.1.1", Proto: "udp", Kind: "residential"}
	same := &Node{ID: "a2", IP: "1.1.1.1", Port: 1195, Proto: "udp", Kind: "residential"}
	viaExit := &Node{ID: "c", IP: "3.3.3.3", ExitIP: "9.9.9.9", Proto: "udp", Kind: "residential"}
	b := &Node{ID: "b", IP: "2.2.2.2", Proto: "udp", Kind: "residential"}
	m.nodes = map[string]*Node{"a": a, "a2": same, "b": b, "c": viaExit}
	m.exits[0] = &Tunnel{Node: &Node{ID: "x", IP: "1.1.1.1"}}
	m.exits[1] = &Tunnel{Node: &Node{ID: "y", IP: "8.8.8.8", ExitIP: "9.9.9.9"}}

	m.mu.Lock()
	got := map[string]bool{}
	for _, n := range m.eligible() {
		got[n.ID] = true
	}
	m.mu.Unlock()
	if len(got) != 1 || !got["b"] {
		t.Fatalf("eligible %v, want only b (others share an IP with an exit)", got)
	}
	if m.ExitRoute(0) != "" {
		t.Error("an exit without a live tunnel must not route")
	}
	if missing := m.missingExits(); len(missing) != 2 {
		t.Errorf("missing %v", missing)
	}
}

func TestExitConfigValidation(t *testing.T) {
	t.Setenv("WEB_PASS", "test")
	t.Setenv("SS_PASSWORD", "sspw")
	t.Setenv("EXITS", "3")
	if _, err := LoadConfig(); err == nil {
		t.Error("EXITS without EXIT_PASS must fail")
	}
	t.Setenv("EXIT_PASS", "pw")
	t.Setenv("EXIT_PORT", "7928")
	if _, err := LoadConfig(); err == nil {
		t.Error("exit ports overlapping SS_PORT must fail")
	}
}
