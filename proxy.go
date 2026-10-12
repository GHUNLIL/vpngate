package main

// HTTP / HTTPS-CONNECT / SOCKS5 on a single port, egressing through the active tunnel.
// After the handshake the relay is TCPConn<->TCPConn io.Copy, which Go turns into splice(2)
// on Linux: zero-copy in the kernel, no user-space buffers.

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	handshakeTimeout = 15 * time.Second
	halfCloseTimeout = 30 * time.Second
)

// Dial opens an upstream connection for host:port.
type Dial func(ctx context.Context, host string, port int) (net.Conn, error)

type Proxy struct {
	Addr     string
	User     string
	Pass     string
	Allow    []*net.IPNet
	MaxConns int64
	Dial     Dial
	// FastConnect answers CONNECT before the upstream handshake finishes, so the client's first
	// bytes (TLS ClientHello) travel in parallel with the tunnel connect: one tunnel RTT saved per
	// connection. A failed connect then shows up as a reset instead of an error reply.
	FastConnect bool

	Active   atomic.Int64
	Total    atomic.Int64
	BytesUp  atomic.Int64
	BytesDn  atomic.Int64
	listener net.Listener
}

type proxyError struct {
	msg        string
	socksCode  byte
	httpStatus string
}

func (e *proxyError) Error() string { return e.msg }

func (p *Proxy) authRequired() bool { return p.User != "" || p.Pass != "" }

func (p *Proxy) checkAuth(user, pass string) bool {
	u := subtle.ConstantTimeCompare([]byte(user), []byte(p.User))
	w := subtle.ConstantTimeCompare([]byte(pass), []byte(p.Pass))
	return u&w == 1
}

func (p *Proxy) allowed(addr net.Addr) bool {
	if len(p.Allow) == 0 {
		return true
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip := tcp.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range p.Allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *Proxy) Listen() error {
	ln, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}
	p.listener = ln
	log.Printf("代理已监听 %s (HTTP / HTTPS / SOCKS5)", ln.Addr())
	return nil
}

func (p *Proxy) Serve() error {
	for {
		c, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if p.Active.Load() >= p.MaxConns || !p.allowed(c.RemoteAddr()) {
			c.Close()
			continue
		}
		go p.handle(c)
	}
}

func (p *Proxy) Close() error { return p.listener.Close() }

func (p *Proxy) handle(client net.Conn) {
	p.Active.Add(1)
	p.Total.Add(1)
	defer p.Active.Add(-1)
	defer client.Close()
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(client, 4096)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	var upstream net.Conn
	if first[0] == 5 {
		upstream, err = p.socks5(client, br)
	} else {
		upstream, err = p.http(client, br)
	}
	if err != nil || upstream == nil {
		return
	}
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})
	// Hand over anything the client pipelined behind the handshake, then relay raw sockets.
	if n := br.Buffered(); n > 0 {
		early, _ := br.Peek(n)
		if _, err := upstream.Write(early); err != nil {
			return
		}
		p.BytesUp.Add(int64(n))
	}
	p.relay(client, upstream)
}

func (p *Proxy) relay(client, upstream net.Conn) {
	done := make(chan error, 2)
	pipe := func(dst, src net.Conn, counter *atomic.Int64) {
		n, err := io.Copy(dst, src)
		counter.Add(n)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- err
	}
	go pipe(upstream, client, &p.BytesUp)
	go pipe(client, upstream, &p.BytesDn)
	if err := <-done; err != nil {
		return // reset/error: tear both sides down now (deferred Close)
	}
	// Clean EOF one way: give the other direction time to drain.
	deadline := time.Now().Add(halfCloseTimeout)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	<-done
}

func (p *Proxy) open(host string, port int) (net.Conn, error) {
	if host == "" || port <= 0 || port > 65535 {
		return nil, &proxyError{"bad target", 1, "400 Bad Request"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	c, err := p.Dial(ctx, host, port)
	if err == nil {
		return c, nil
	}
	var pe *proxyError
	var ne net.Error
	switch {
	case errors.As(err, &pe):
		return nil, pe
	case errors.Is(err, errBlocked):
		return nil, &proxyError{err.Error(), 2, "403 Forbidden"}
	case errors.As(err, &ne) && ne.Timeout():
		return nil, &proxyError{fmt.Sprintf("%s:%d 连接超时", host, port), 4, "504 Gateway Timeout"}
	default:
		return nil, &proxyError{fmt.Sprintf("%s:%d %v", host, port, err), 5, "502 Bad Gateway"}
	}
}

// ---------------------------------------------------------------- SOCKS5

func (p *Proxy) socks5(client net.Conn, br *bufio.Reader) (net.Conn, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, err
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return nil, err
	}
	want := byte(0)
	if p.authRequired() {
		want = 2
	}
	if !strings.ContainsRune(string(methods), rune(want)) {
		_, _ = client.Write([]byte{5, 0xff})
		return nil, nil
	}
	if _, err := client.Write([]byte{5, want}); err != nil {
		return nil, err
	}
	if want == 2 {
		user, pass, err := readUserPass(br)
		if err != nil {
			return nil, err
		}
		if !p.checkAuth(user, pass) {
			_, _ = client.Write([]byte{1, 1})
			return nil, nil
		}
		if _, err := client.Write([]byte{1, 0}); err != nil {
			return nil, err
		}
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return nil, err
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	default:
		_, _ = client.Write(socksReply(8))
		return nil, nil
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return nil, err
	}
	if req[1] != 1 { // CONNECT only
		_, _ = client.Write(socksReply(7))
		return nil, nil
	}
	port := int(binary.BigEndian.Uint16(pb))
	if p.FastConnect {
		if _, err := client.Write(socksReply(0)); err != nil {
			return nil, err
		}
		return p.openOrReset(client, host, port)
	}
	up, err := p.open(host, port)
	if err != nil {
		_, _ = client.Write(socksReply(err.(*proxyError).socksCode))
		return nil, nil
	}
	if _, err := client.Write(socksReply(0)); err != nil {
		up.Close()
		return nil, err
	}
	return up, nil
}

func readUserPass(br *bufio.Reader) (string, string, error) {
	field := func() (string, error) {
		l, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, l)
		_, err = io.ReadFull(br, b)
		return string(b), err
	}
	if _, err := br.ReadByte(); err != nil { // sub-negotiation version
		return "", "", err
	}
	user, err := field()
	if err != nil {
		return "", "", err
	}
	pass, err := field()
	return user, pass, err
}

// openOrReset dials after a success reply was already sent; on failure the client gets a TCP RST
// so it fails fast rather than waiting on a dead connection.
func (p *Proxy) openOrReset(client net.Conn, host string, port int) (net.Conn, error) {
	up, err := p.open(host, port)
	if err != nil {
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		return nil, nil
	}
	return up, nil
}

func socksReply(code byte) []byte { return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0} }

// ---------------------------------------------------------------- HTTP

var hopHeaders = map[string]bool{"proxy-authorization": true, "proxy-connection": true, "connection": true,
	"keep-alive": true}

func (p *Proxy) http(client net.Conn, br *bufio.Reader) (net.Conn, error) {
	var lines []string
	size := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if size += len(line); size > 64<<10 {
			return nil, httpFail(client, "431 Request Header Fields Too Large")
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, httpFail(client, "400 Bad Request")
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 {
		return nil, httpFail(client, "400 Bad Request")
	}
	method, target, version := parts[0], parts[1], parts[2]
	headers := lines[1:]
	if p.authRequired() && !p.httpAuth(headers) {
		_, _ = io.WriteString(client, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"VPNGATE\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return nil, nil
	}
	if strings.EqualFold(method, "CONNECT") {
		host, port := splitHostPort(target, 443)
		if p.FastConnect {
			if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return nil, err
			}
			return p.openOrReset(client, host, port)
		}
		up, err := p.open(host, port)
		if err != nil {
			return nil, httpFail(client, err.(*proxyError).httpStatus)
		}
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			up.Close()
			return nil, err
		}
		return up, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return nil, httpFail(client, "400 Bad Request")
	}
	port := 80
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	}
	up, err := p.open(u.Hostname(), port)
	if err != nil {
		return nil, httpFail(client, err.(*proxyError).httpStatus)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, u.RequestURI(), version)
	for _, h := range headers {
		name, _, _ := strings.Cut(h, ":")
		if !hopHeaders[strings.ToLower(strings.TrimSpace(name))] {
			b.WriteString(h + "\r\n")
		}
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(up, b.String()); err != nil {
		up.Close()
		return nil, err
	}
	return up, nil
}

func (p *Proxy) httpAuth(headers []string) bool {
	for _, h := range headers {
		name, value, _ := strings.Cut(h, ":")
		if !strings.EqualFold(strings.TrimSpace(name), "proxy-authorization") {
			continue
		}
		scheme, token, _ := strings.Cut(strings.TrimSpace(value), " ")
		if !strings.EqualFold(scheme, "basic") {
			return false
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
		if err != nil {
			return false
		}
		user, pass, _ := strings.Cut(string(raw), ":")
		return p.checkAuth(user, pass)
	}
	return false
}

func httpFail(client net.Conn, status string) error {
	_, _ = io.WriteString(client, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	return errors.New(status)
}

func splitHostPort(authority string, def int) (string, int) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.Trim(authority, "[]"), def
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return host, def
	}
	return host, p
}

// TunnelDialer connects through whichever tunnel is currently active.
func TunnelDialer(res *Resolver, route func() string) Dial {
	return func(ctx context.Context, host string, port int) (net.Conn, error) {
		dev := route()
		if dev == "" {
			return nil, &proxyError{"没有可用的隧道", 1, "503 Service Unavailable"}
		}
		c, err := DialVia(ctx, res, host, port, dev, 10*time.Second)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				return nil, &proxyError{"DNS 解析失败: " + host, 4, "502 Bad Gateway"}
			}
			return nil, err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		return c, nil
	}
}
