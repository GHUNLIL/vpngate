package main

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- shadowsocks

type ssRig struct {
	mu      sync.Mutex
	targets []string
}

// newSSRig starts a server whose TCP upstream is a local echo server, recording requested targets.
func newSSRig(t *testing.T) (*SSServer, *ssCipher, *ssRig) {
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
	rig := &ssRig{}
	dial := func(ctx context.Context, host string, port int) (net.Conn, error) {
		rig.mu.Lock()
		rig.targets = append(rig.targets, net.JoinHostPort(host, strconv.Itoa(port)))
		rig.mu.Unlock()
		return net.Dial("tcp", echo.Addr().String())
	}
	c, err := newSSCipher("aes-128-gcm", "secret")
	if err != nil {
		t.Fatal(err)
	}
	s := &SSServer{Addr: "127.0.0.1:0", Cipher: c, Allow: func(net.IP) bool { return true },
		Dial: dial, Res: NewResolver(nil), Route: func() string { return "test0" }, allowPrivate: true,
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

func TestSourceAllowed(t *testing.T) {
	_, n, _ := net.ParseCIDR("203.0.113.0/24")
	allow := []*net.IPNet{n}
	for ip, want := range map[string]bool{"127.0.0.1": true, "203.0.113.9": true, "198.51.100.1": false} {
		if got := sourceAllowed(allow, net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %v", ip, got)
		}
	}
	if !sourceAllowed(nil, net.ParseIP("198.51.100.1")) {
		t.Error("empty list allows everyone")
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
