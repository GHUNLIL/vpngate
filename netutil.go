package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// dialer returns a low-latency TCP dialer bound to dev ("" = default route).
func dialer(dev string, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: bindControl(dev),
		KeepAliveConfig: net.KeepAliveConfig{
			Enable: true, Idle: 60 * time.Second, Interval: 10 * time.Second, Count: 3,
		},
	}
}

var cgnatNet = mustCIDR("100.64.0.0/10")

func isPublicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnatNet.Contains(ip)
}

// TCPRTT measures a TCP handshake; nil when unreachable.
func TCPRTT(ctx context.Context, ip string, port int, dev string, timeout time.Duration) *float64 {
	start := time.Now()
	c, err := dialer(dev, timeout).DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	rtt := float64(time.Since(start).Microseconds()) / 1000
	c.Close()
	return &rtt
}

// ---------------------------------------------------------------- ICMP

type PingStats struct {
	Sent int
	RTTs []float64
}

func (p PingStats) LossPct() float64 {
	if p.Sent == 0 {
		return 100
	}
	return 100 * float64(p.Sent-len(p.RTTs)) / float64(p.Sent)
}

func (p PingStats) Avg() *float64 {
	if len(p.RTTs) == 0 {
		return nil
	}
	sum := 0.0
	for _, r := range p.RTTs {
		sum += r
	}
	return ptr(sum / float64(len(p.RTTs)))
}

// Jitter is the mean absolute difference between consecutive samples (RFC 3550 style).
func (p PingStats) Jitter() float64 {
	if len(p.RTTs) < 2 {
		return 0
	}
	sum := 0.0
	for i := 1; i < len(p.RTTs); i++ {
		d := p.RTTs[i] - p.RTTs[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return sum / float64(len(p.RTTs)-1)
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func echoRequest(id, seq uint16) []byte {
	pkt := make([]byte, 8+16)
	pkt[0] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	_, _ = rand.Read(pkt[8:])
	binary.BigEndian.PutUint16(pkt[2:], icmpChecksum(pkt))
	return pkt
}

// Ping sends ICMP echo requests over a raw socket (root / CAP_NET_RAW). Never fails: errors count as loss.
func Ping(ctx context.Context, ip string, count int, interval, timeout time.Duration, dev string) PingStats {
	stats := PingStats{Sent: count}
	target := net.ParseIP(ip)
	lc := net.ListenConfig{Control: bindControl(dev)}
	conn, err := lc.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil || target == nil {
		return stats
	}
	defer conn.Close()
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])

	var mu sync.Mutex
	sent := map[uint16]time.Time{}
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(count-1)*interval + timeout))
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for got := 0; got < count; {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			now := time.Now()
			addr, _ := from.(*net.IPAddr)
			if n < 8 || buf[0] != 0 || addr == nil || !addr.IP.Equal(target) ||
				binary.BigEndian.Uint16(buf[4:]) != id {
				continue
			}
			seq := binary.BigEndian.Uint16(buf[6:])
			mu.Lock()
			if t, ok := sent[seq]; ok {
				delete(sent, seq)
				stats.RTTs = append(stats.RTTs, float64(now.Sub(t).Microseconds())/1000)
				got++
			}
			mu.Unlock()
		}
	}()
	for seq := 0; seq < count; seq++ {
		mu.Lock()
		sent[uint16(seq)] = time.Now()
		mu.Unlock()
		_, _ = conn.WriteTo(echoRequest(id, uint16(seq)), &net.IPAddr{IP: target})
		if seq < count-1 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				_ = conn.SetReadDeadline(time.Now())
			}
		}
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return PingStats{Sent: count, RTTs: append([]float64(nil), stats.RTTs...)}
}

// ---------------------------------------------------------------- DNS

const (
	dnsFresh = 2 * time.Minute  // answer from cache, no refresh
	dnsStale = 30 * time.Minute // answer from cache instantly, refresh in the background
)

type dnsEntry struct {
	ips     []net.IP
	fetched time.Time
}

type dnsCall struct {
	done chan struct{}
	ips  []net.IP
	err  error
}

// Resolver looks up IPv4 addresses through the tunnel device (so CDNs see a Japanese resolver) and
// caches answers stale-while-revalidate: a repeat visit never waits on DNS. Concurrent lookups of
// the same name share one query.
type Resolver struct {
	servers  []string
	mu       sync.Mutex
	cache    map[string]dnsEntry
	inflight map[string]*dnsCall
}

func NewResolver(servers []string) *Resolver {
	return &Resolver{servers: servers, cache: map[string]dnsEntry{}, inflight: map[string]*dnsCall{}}
}

func (r *Resolver) Resolve(ctx context.Context, host, dev string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	r.mu.Lock()
	e, cached := r.cache[host]
	age := time.Since(e.fetched)
	if cached && age < dnsStale {
		if age >= dnsFresh && r.inflight[host] == nil {
			r.startLocked(host, dev)
		}
		r.mu.Unlock()
		return e.ips, nil
	}
	call := r.inflight[host]
	if call == nil {
		call = r.startLocked(host, dev)
	}
	r.mu.Unlock()
	select {
	case <-call.done:
		return call.ips, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startLocked runs a lookup detached from any one request, so a cancelled client cannot fail
// the query for everyone waiting on it. Caller holds r.mu.
func (r *Resolver) startLocked(host, dev string) *dnsCall {
	call := &dnsCall{done: make(chan struct{})}
	r.inflight[host] = call
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		call.ips, call.err = r.lookup(ctx, host, dev)
		r.mu.Lock()
		delete(r.inflight, host)
		if call.err == nil {
			if len(r.cache) > 16384 {
				r.cache = map[string]dnsEntry{}
			}
			r.cache[host] = dnsEntry{call.ips, time.Now()}
		}
		r.mu.Unlock()
		close(call.done)
	}()
	return call
}

func (r *Resolver) lookup(ctx context.Context, host, dev string) ([]net.IP, error) {
	fqdn := host + "." // no search-domain expansion
	for _, server := range r.servers {
		addr := net.JoinHostPort(server, "53")
		res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1500 * time.Millisecond, Control: bindControl(dev)}
			return d.DialContext(ctx, network, addr)
		}}
		qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ips, err := res.LookupIP(qctx, "ip4", fqdn)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, err
		}
	}
	// Fall back to the system resolver (the VPS is in Japan, still a sensible answer).
	return net.DefaultResolver.LookupIP(ctx, "ip4", fqdn)
}

// DialVia resolves host through dev and connects to the first reachable public address.
func DialVia(ctx context.Context, r *Resolver, host string, port int, dev string, timeout time.Duration) (net.Conn, error) {
	ips, err := r.Resolve(ctx, host, dev)
	if err != nil {
		return nil, err
	}
	var last error = errors.New("no address")
	for i, ip := range ips {
		if i == 2 {
			break
		}
		if !isPublicIP(ip) {
			return nil, errBlocked
		}
		c, err := dialer(dev, timeout).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

var errBlocked = errors.New("拒绝访问内网地址")

// ---------------------------------------------------------------- HTTP (diagnostics)

func httpClient(r *Resolver, dev string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			p, _ := strconv.Atoi(port)
			return DialVia(ctx, r, host, p, dev, timeout)
		},
	}}
}

// HTTPGet fetches a small document through dev.
func HTTPGet(ctx context.Context, r *Resolver, url, dev string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient(r, dev, 6*time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// SpeedTest downloads n bytes through dev and returns Mbps measured over the body transfer.
func SpeedTest(ctx context.Context, r *Resolver, url, dev string) (float64, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := httpClient(r, dev, 15*time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, errors.New(resp.Status)
	}
	start := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	secs := time.Since(start).Seconds()
	if err != nil || secs <= 0 || n == 0 {
		return 0, errors.New("测速失败")
	}
	return float64(n) * 8 / secs / 1e6, nil
}
