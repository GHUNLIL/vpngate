package main

// Shadowsocks AEAD server (aes-128-gcm / aes-256-gcm, SIP004 / SIP022-compatible framing):
// encrypted TCP and UDP from the client, egressing through the active tunnel.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	handshakeTimeout = 15 * time.Second
	halfCloseTimeout = 30 * time.Second

	ssMaxPayload   = 0x3FFF
	ssTagSize      = 16
	ssUDPIdle      = 2 * time.Minute
	ssMaxAssocs    = 4096
	ssReplayWindow = 1 << 15 // salts remembered for replay protection
)

// Dial opens an upstream TCP connection for host:port.
type Dial func(ctx context.Context, host string, port int) (net.Conn, error)

var errNoTunnel = errors.New("没有可用的隧道")

// TunnelDialer connects through whichever tunnel is currently active.
func TunnelDialer(res *Resolver, route func() string) Dial {
	return func(ctx context.Context, host string, port int) (net.Conn, error) {
		dev := route()
		if dev == "" {
			return nil, errNoTunnel
		}
		return DialVia(ctx, res, host, port, dev, 10*time.Second)
	}
}

// sourceAllowed applies the SS_ALLOW list (empty = everyone); loopback is always allowed.
func sourceAllowed(allow []*net.IPNet, ip net.IP) bool {
	if len(allow) == 0 {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- crypto

type ssCipher struct {
	key []byte
}

func newSSCipher(method, password string) (*ssCipher, error) {
	size := map[string]int{"aes-128-gcm": 16, "aes-256-gcm": 32}[method]
	if size == 0 {
		return nil, fmt.Errorf("不支持的 Shadowsocks 加密方式 %q (可选 aes-128-gcm / aes-256-gcm)", method)
	}
	return &ssCipher{key: evpBytesToKey(password, size)}, nil
}

func (c *ssCipher) saltSize() int { return len(c.key) }

// aead derives the per-session subkey: HKDF-SHA1(master key, salt, "ss-subkey").
func (c *ssCipher) aead(salt []byte) (cipher.AEAD, error) {
	sub, err := hkdf.Key(sha1.New, c.key, salt, "ss-subkey", len(c.key))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// evpBytesToKey is OpenSSL's password-to-key derivation, as used by every Shadowsocks client.
func evpBytesToKey(password string, keyLen int) []byte {
	var key, prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keyLen]
}

func incNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// ssReader decrypts a TCP chunk stream: [len+tag][payload+tag]...
type ssReader struct {
	r     io.Reader
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
	left  []byte
}

func newSSReader(r io.Reader, aead cipher.AEAD) *ssReader {
	return &ssReader{r: r, aead: aead, nonce: make([]byte, aead.NonceSize()), buf: make([]byte, ssMaxPayload+ssTagSize)}
}

func (s *ssReader) Read(p []byte) (int, error) {
	if len(s.left) == 0 {
		hdr := s.buf[:2+ssTagSize]
		if _, err := io.ReadFull(s.r, hdr); err != nil {
			return 0, err
		}
		plain, err := s.aead.Open(hdr[:0], s.nonce, hdr, nil)
		if err != nil {
			return 0, errSSAuth
		}
		incNonce(s.nonce)
		size := int(binary.BigEndian.Uint16(plain)) & ssMaxPayload
		chunk := s.buf[:size+ssTagSize]
		if _, err := io.ReadFull(s.r, chunk); err != nil {
			return 0, err
		}
		if s.left, err = s.aead.Open(chunk[:0], s.nonce, chunk, nil); err != nil {
			return 0, errSSAuth
		}
		incNonce(s.nonce)
	}
	n := copy(p, s.left)
	s.left = s.left[n:]
	return n, nil
}

// ssWriter encrypts into the chunk stream; the salt is sent with the first chunk.
type ssWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	salt  []byte
	nonce []byte
	buf   []byte
}

func newSSWriter(w io.Writer, c *ssCipher) (*ssWriter, error) {
	salt := make([]byte, c.saltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := c.aead(salt)
	if err != nil {
		return nil, err
	}
	return &ssWriter{w: w, aead: aead, salt: salt, nonce: make([]byte, aead.NonceSize()),
		buf: make([]byte, 0, len(salt)+2+ssTagSize+ssMaxPayload+ssTagSize)}, nil
}

func (s *ssWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), ssMaxPayload)
		buf := append(s.buf[:0], s.salt...)
		s.salt = nil
		buf = s.aead.Seal(buf, s.nonce, []byte{byte(n >> 8), byte(n)}, nil)
		incNonce(s.nonce)
		buf = s.aead.Seal(buf, s.nonce, p[:n], nil)
		incNonce(s.nonce)
		if _, err := s.w.Write(buf); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

var errSSAuth = errors.New("shadowsocks: authentication failed")

// ---------------------------------------------------------------- SOCKS address

func readSocksAddr(r io.Reader) (string, int, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", 0, err
	}
	atyp := b[0]
	var host []byte
	switch atyp {
	case 1:
		host = make([]byte, 4)
	case 4:
		host = make([]byte, 16)
	case 3:
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = make([]byte, b[0])
	default:
		return "", 0, errSSAuth
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, host); err != nil {
		return "", 0, err
	}
	if _, err := io.ReadFull(r, port); err != nil {
		return "", 0, err
	}
	h := string(host)
	if atyp != 3 {
		h = net.IP(host).String()
	}
	return h, int(binary.BigEndian.Uint16(port)), nil
}

func parseSocksAddr(b []byte) (host string, port int, n int, err error) {
	if len(b) < 1 {
		return "", 0, 0, errSSAuth
	}
	switch b[0] {
	case 1:
		n = 1 + 4
		if len(b) >= n+2 {
			host = net.IP(b[1:n]).String()
		}
	case 4:
		n = 1 + 16
		if len(b) >= n+2 {
			host = net.IP(b[1:n]).String()
		}
	case 3:
		if len(b) < 2 {
			return "", 0, 0, errSSAuth
		}
		n = 2 + int(b[1])
		if len(b) >= n+2 {
			host = string(b[2:n])
		}
	}
	if host == "" {
		return "", 0, 0, errSSAuth
	}
	return host, int(binary.BigEndian.Uint16(b[n:])), n + 2, nil
}

func socksAddrBytes(ap netip.AddrPort) []byte {
	a := ap.Addr().Unmap()
	var out []byte
	if a.Is4() {
		ip := a.As4()
		out = append([]byte{1}, ip[:]...)
	} else {
		ip := a.As16()
		out = append([]byte{4}, ip[:]...)
	}
	return binary.BigEndian.AppendUint16(out, ap.Port())
}

// ---------------------------------------------------------------- replay filter

type saltFilter struct {
	mu   sync.Mutex
	seen map[string]struct{}
	ring []string
	pos  int
}

func newSaltFilter(size int) *saltFilter {
	return &saltFilter{seen: map[string]struct{}{}, ring: make([]string, size)} // map grows with use
}

// add records a salt; false means it was seen before (a replayed handshake).
func (f *saltFilter) add(salt []byte) bool {
	key := string(salt)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.seen[key]; dup {
		return false
	}
	if old := f.ring[f.pos]; old != "" {
		delete(f.seen, old)
	}
	f.ring[f.pos] = key
	f.pos = (f.pos + 1) % len(f.ring)
	f.seen[key] = struct{}{}
	return true
}

// ---------------------------------------------------------------- server

type SSServer struct {
	Addr     string
	Cipher   *ssCipher
	Allow    func(net.IP) bool
	MaxConns int64
	Dial     Dial
	Res      *Resolver
	Route    func() string

	Active atomic.Int64 // open TCP connections (for SS_MAX_CONNS)

	allowPrivate bool                                     // tests only: permit loopback UDP targets
	listenUDP    func(dev string) (net.PacketConn, error) // tests only: replaces the device-bound socket
	salts        *saltFilter
	ln           net.Listener
	pc           *net.UDPConn
	mu           sync.Mutex
	assocs       map[netip.AddrPort]*udpAssoc
}

func (s *SSServer) Listen() error {
	s.salts = newSaltFilter(ssReplayWindow)
	s.assocs = map[netip.AddrPort]*udpAssoc{}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	ua, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		ln.Close()
		return err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		ln.Close()
		return err
	}
	s.ln, s.pc = ln, pc
	log.Printf("Shadowsocks 已监听 %s (TCP + UDP)", ln.Addr())
	return nil
}

func (s *SSServer) Serve() {
	go s.serveUDP()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if tcp, ok := c.RemoteAddr().(*net.TCPAddr); !ok || !s.Allow(tcp.IP) ||
			s.MaxConns > 0 && s.Active.Load() >= s.MaxConns {
			c.Close()
			continue
		}
		go s.handleTCP(c)
	}
}

func (s *SSServer) Close() {
	s.ln.Close()
	s.pc.Close()
}

// stall keeps a failed connection open and silent so active probes learn nothing.
func stall(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	_, _ = io.Copy(io.Discard, c)
}

func (s *SSServer) handleTCP(c net.Conn) {
	s.Active.Add(1)
	defer s.Active.Add(-1)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	salt := make([]byte, s.Cipher.saltSize())
	if _, err := io.ReadFull(c, salt); err != nil {
		return
	}
	aead, err := s.Cipher.aead(salt)
	if err != nil {
		return
	}
	r := newSSReader(c, aead)
	host, port, err := readSocksAddr(r)
	if err != nil {
		stall(c)
		return
	}
	if !s.salts.add(salt) {
		stall(c)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	up, err := s.Dial(ctx, host, port)
	cancel()
	if err != nil {
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	w, err := newSSWriter(c, s.Cipher)
	if err != nil {
		return
	}

	done := make(chan error, 2)
	go func() { // client -> target
		_, err := io.Copy(up, r)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- err
	}()
	go func() {
		_, err := io.Copy(w, up)
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

// ---------------------------------------------------------------- UDP

type udpAssoc struct {
	client netip.AddrPort
	out    net.PacketConn
	dev    string
	queue  chan []byte
	done   chan struct{}
	once   sync.Once
	last   atomic.Int64
}

func (a *udpAssoc) close() {
	a.once.Do(func() {
		close(a.done)
		a.out.Close()
	})
}

func (s *SSServer) serveUDP() {
	buf := make([]byte, 64<<10)
	zero := make([]byte, 12)
	for {
		n, client, err := s.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ss := s.Cipher.saltSize()
		if n < ss+ssTagSize || !s.Allow(net.IP(client.Addr().Unmap().AsSlice())) {
			continue
		}
		aead, err := s.Cipher.aead(buf[:ss])
		if err != nil {
			continue
		}
		plain, err := aead.Open(nil, zero, buf[ss:n], nil)
		if err != nil {
			continue
		}
		a := s.assoc(client)
		if a == nil {
			continue
		}
		select {
		case a.queue <- plain:
		default: // drop under pressure, like any UDP path
		}
	}
}

func (s *SSServer) assoc(client netip.AddrPort) *udpAssoc {
	dev := s.Route()
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.assocs[client]; a != nil {
		if a.dev == dev {
			return a
		}
		// The active tunnel changed (failover / re-selection): move the flow to the new one.
		delete(s.assocs, client)
		a.close()
	}
	if dev == "" || len(s.assocs) >= ssMaxAssocs {
		return nil
	}
	listen := s.listenUDP
	if listen == nil {
		listen = func(dev string) (net.PacketConn, error) {
			lc := net.ListenConfig{Control: bindControl(dev)}
			return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
		}
	}
	out, err := listen(dev)
	if err != nil {
		return nil
	}
	a := &udpAssoc{client: client, out: out, dev: dev, queue: make(chan []byte, 256), done: make(chan struct{})}
	a.last.Store(time.Now().UnixNano())
	s.assocs[client] = a
	go s.udpSend(a)
	go s.udpReceive(a)
	return a
}

// udpSend forwards client datagrams to their targets through the tunnel.
func (s *SSServer) udpSend(a *udpAssoc) {
	for {
		var plain []byte
		select {
		case plain = <-a.queue:
		case <-a.done:
			return
		}
		host, port, hl, err := parseSocksAddr(plain)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := s.Res.Resolve(ctx, host, a.dev)
		cancel()
		if err != nil || len(ips) == 0 || ips[0].To4() == nil || !s.allowPrivate && !isPublicIP(ips[0]) {
			continue
		}
		a.last.Store(time.Now().UnixNano())
		_, _ = a.out.WriteTo(plain[hl:], &net.UDPAddr{IP: ips[0], Port: port})
	}
}

// udpReceive relays replies back to the client, encrypted, until the association goes idle.
func (s *SSServer) udpReceive(a *udpAssoc) {
	defer func() {
		s.mu.Lock()
		if s.assocs[a.client] == a {
			delete(s.assocs, a.client)
		}
		s.mu.Unlock()
		a.close()
	}()
	buf := make([]byte, 64<<10)
	zero := make([]byte, 12)
	for {
		_ = a.out.SetReadDeadline(time.Now().Add(ssUDPIdle))
		n, from, err := a.out.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() &&
				time.Since(time.Unix(0, a.last.Load())) < ssUDPIdle {
				continue // client still sending: keep the association
			}
			return
		}
		src, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		a.last.Store(time.Now().UnixNano())
		salt := make([]byte, s.Cipher.saltSize())
		if _, err := rand.Read(salt); err != nil {
			continue
		}
		aead, err := s.Cipher.aead(salt)
		if err != nil {
			continue
		}
		payload := append(socksAddrBytes(src.AddrPort()), buf[:n]...)
		_, _ = s.pc.WriteToUDPAddrPort(aead.Seal(salt, zero, payload, nil), a.client)
	}
}

// SSURI renders a SIP002 link for clients.
func SSURI(method, password, host string, port int, name string) string {
	user := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	return "ss://" + user + "@" + net.JoinHostPort(host, strconv.Itoa(port)) + "#" + name
}
