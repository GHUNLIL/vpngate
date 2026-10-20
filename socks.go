package main

// Plain SOCKS5 (CONNECT only, RFC 1928 + username/password RFC 1929) for the exit pool: one
// listener per exit tunnel, so a program that takes a socks5:// proxy per account gets a fixed exit
// IP per account. Meant for local or private-network clients; it is not encrypted.

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const socksMaxConns = 1024 // per listener

type SocksServer struct {
	Addr  string
	User  string
	Pass  string // empty = no authentication
	Allow func(net.IP) bool
	Dial  Dial

	Active atomic.Int64
	ln     net.Listener
}

func (s *SocksServer) Listen() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

func (s *SocksServer) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if tcp, ok := c.RemoteAddr().(*net.TCPAddr); !ok || !s.Allow(tcp.IP) || s.Active.Load() >= socksMaxConns {
			c.Close()
			continue
		}
		go s.handle(c)
	}
}

func (s *SocksServer) Close() { s.ln.Close() }

func (s *SocksServer) handle(c net.Conn) {
	s.Active.Add(1)
	defer s.Active.Add(-1)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	if !s.greet(c) {
		return
	}
	var req [3]byte // VER CMD RSV
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	host, port, err := readSocksAddr(c)
	if err != nil {
		return
	}
	if req[1] != 1 { // CONNECT only
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	up, err := s.Dial(ctx, host, port)
	cancel()
	if err != nil {
		code := byte(1) // general failure
		if errors.Is(err, errBlocked) {
			code = 2 // not allowed by ruleset
		}
		_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(up, c)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- err
	}()
	go func() {
		_, err := io.Copy(c, up)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- err
	}()
	if err := <-done; err != nil {
		return
	}
	deadline := time.Now().Add(halfCloseTimeout)
	_ = c.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)
	<-done
}

// greet negotiates the auth method and checks the credentials; false closes the connection.
func (s *SocksServer) greet(c net.Conn) bool {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return false
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return false
	}
	want := byte(0)
	if s.Pass != "" {
		want = 2
	}
	offered := false
	for _, m := range methods {
		offered = offered || m == want
	}
	if !offered {
		_, _ = c.Write([]byte{5, 0xff})
		return false
	}
	if _, err := c.Write([]byte{5, want}); err != nil || want == 0 {
		return err == nil
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[0] != 1 {
		return false
	}
	user, err := readShort(c)
	if err != nil {
		return false
	}
	pass, err := readShort(c)
	if err != nil {
		return false
	}
	ok := subtle.ConstantTimeCompare([]byte(user), []byte(s.User)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(s.Pass)) == 1
	if !ok {
		log.Printf("SOCKS5 %s: 来自 %s 的认证失败", s.Addr, c.RemoteAddr())
		_, _ = c.Write([]byte{1, 1})
		return false
	}
	_, err = c.Write([]byte{1, 0})
	return err == nil
}

// readShort reads a one-byte length followed by that many bytes.
func readShort(r io.Reader) (string, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return "", err
	}
	b := make([]byte, n[0])
	_, err := io.ReadFull(r, b)
	return string(b), err
}
