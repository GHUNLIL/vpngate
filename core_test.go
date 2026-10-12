package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) []byte {
	data, err := os.ReadFile("testdata/servers.csv")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseCSV(t *testing.T) {
	jp := ParseCSV(fixture(t), []string{"JP"})
	if len(jp) != 3 {
		t.Fatalf("want 3 JP nodes, got %d", len(jp))
	}
	protos := map[string]bool{}
	for _, n := range jp {
		protos[n.Proto] = true
		if n.Country != "JP" || !strings.Contains(n.Config, "remote "+n.IP) {
			t.Errorf("bad node %+v", n.ID)
		}
	}
	if !protos["tcp"] || !protos["udp"] {
		t.Errorf("want both protocols, got %v", protos)
	}
	if all := ParseCSV(fixture(t), nil); len(all) <= len(jp) {
		t.Errorf("no-country filter returned %d", len(all))
	}
}

func TestParseRemote(t *testing.T) {
	if p, h, port := ParseRemote("proto tcp-client\nremote 1.2.3.4 995\n", "9.9.9.9"); p != "tcp" || h != "1.2.3.4" || port != 995 {
		t.Errorf("got %s %s %d", p, h, port)
	}
	if p, h, port := ParseRemote("client\n", "9.9.9.9"); p != "udp" || h != "9.9.9.9" || port != 1194 {
		t.Errorf("got %s %s %d", p, h, port)
	}
}

func TestClassify(t *testing.T) {
	academic := &Node{IP: "219.100.37.5"}
	home := &Node{IP: "1.2.3.4"}
	cases := []struct {
		info ipInfo
		node *Node
		want string
	}{
		{ipInfo{Status: "success"}, academic, "academic"},
		{ipInfo{Status: "fail"}, home, "unknown"},
		{ipInfo{Status: "success", Hosting: true}, home, "hosting"},
		{ipInfo{Status: "success", ISP: "Vultr Holdings"}, home, "hosting"},
		{ipInfo{Status: "success", Mobile: true}, home, "mobile"},
		{ipInfo{Status: "success", ISP: "NTT Communications"}, home, "residential"},
	}
	for _, c := range cases {
		if got := Classify(c.info, c.node); got != c.want {
			t.Errorf("Classify(%+v) = %s, want %s", c.info, got, c.want)
		}
	}
}

func TestSelectionRule(t *testing.T) {
	mk := func(id string, rtt, mbps float64) *Node { return &Node{ID: id, RTT: ptr(rtt), Mbps: ptr(mbps)} }
	fastLowLat := mk("a", 30, 60)   // qualified, lowest latency -> wins
	fastHighLat := mk("b", 45, 150) // qualified, faster but slower latency
	slowLowLat := mk("c", 20, 40)   // lowest latency but below 50 Mbps
	slower := mk("d", 25, 10)
	untested := &Node{ID: "e"}
	lossy := mk("f", 10, 200) // fastest and lowest latency, but 10% loss -> not qualified
	lossy.Loss = ptr(10)
	worse := mk("g", 5, 300) // even lossier: among unqualified, less loss ranks first
	worse.Loss = ptr(90)
	nodes := []*Node{untested, worse, lossy, slower, slowLowLat, fastHighLat, fastLowLat}
	sort.SliceStable(nodes, func(i, j int) bool { return Better(nodes[i], nodes[j], 50) })
	var ids []string
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	if strings.Join(ids, "") != "abcdfge" {
		t.Errorf("ranking %v, want qualified by latency, then unqualified by speed, then untested", ids)
	}
	if !fastLowLat.Qualified(50) || slowLowLat.Qualified(50) || untested.Qualified(0) {
		t.Error("qualification")
	}
}

func TestFetchFallsBackToCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "servers.csv")
	_ = os.WriteFile(cache, fixture(t), 0o600)
	data, err := FetchCSV(context.Background(), []string{"http://127.0.0.1:9/"}, cache)
	if err != nil || len(data) == 0 {
		t.Fatalf("expected cache fallback, got %v", err)
	}
	_ = os.Remove(cache)
	if _, err := FetchCSV(context.Background(), []string{"http://127.0.0.1:9/"}, cache); err == nil {
		t.Fatal("expected error without cache")
	}
}

func TestPingStats(t *testing.T) {
	s := PingStats{Sent: 4, RTTs: []float64{10, 12, 11}}
	if s.LossPct() != 25 || *s.Avg() != 11 || s.Jitter() != 1.5 {
		t.Errorf("loss %v avg %v jitter %v", s.LossPct(), *s.Avg(), s.Jitter())
	}
	if (PingStats{Sent: 3}).LossPct() != 100 {
		t.Error("empty stats should be 100% loss")
	}
}

func TestICMPChecksum(t *testing.T) {
	pkt := echoRequest(0x1234, 7, 1200)
	if icmpChecksum(pkt) != 0 { // a packet with a valid checksum sums to zero
		t.Error("bad checksum")
	}
}

func TestIsPublicIP(t *testing.T) {
	if !isPublicIP(net.ParseIP("1.1.1.1")) {
		t.Error("1.1.1.1 should be public")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "::1", "0.0.0.0"} {
		if isPublicIP(net.ParseIP(ip)) {
			t.Errorf("%s should not be public", ip)
		}
	}
}

func TestOpenVPNArgs(t *testing.T) {
	udp := strings.Join(OpenVPNArgs("/c.ovpn", "/a", "vg3", "udp", [2]int{2, 6}), " ")
	for _, want := range []string{"--dev vg3", "--route-nopull", "--fast-io", "--sndbuf 4194304", "--mssfix 1360",
		"--data-ciphers AES-128-GCM", "--data-ciphers-fallback AES-128-CBC", "--ping-exit 25",
		"--explicit-exit-notify 1", "--tun-mtu 1400"} {
		if !strings.Contains(udp, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Index(udp, "--config") > strings.Index(udp, "--data-ciphers") {
		t.Error("CLI options must come after --config to override the file")
	}
	tcp := strings.Join(OpenVPNArgs("/c", "/a", "vg0", "tcp", [2]int{2, 4}), " ")
	if strings.Contains(tcp, "--fast-io") || strings.Contains(tcp, "--data-ciphers") ||
		strings.Contains(tcp, "--explicit-exit-notify") {
		t.Error("tcp / OpenVPN 2.4 must not get UDP or NCP options")
	}
}

func TestPushedOptionWarningIsNotFatal(t *testing.T) {
	warn := strings.ToLower("Options error: option 'dhcp-option' cannot be used in this context ([PUSH-OPTIONS])")
	if containsAny(warn, fatalMarkers) {
		t.Error("pushed-option warning must not abort the handshake")
	}
	if !containsAny("exiting due to fatal error", fatalMarkers) || !containsAny("auth_failed", fatalMarkers) {
		t.Error("real failures must be fatal")
	}
}

func TestNativeUDPVariants(t *testing.T) {
	html := []byte(`<a href='do_openvpn.aspx?fqdn=a.opengw.net&amp;ip=1.2.3.4&amp;tcp=1605&amp;udp=1915&amp;sid=1'>` +
		`<a href='do_openvpn.aspx?fqdn=b.opengw.net&ip=5.6.7.8&tcp=443&udp=0&sid=2'>`)
	ports := ParseUDPPorts(html)
	if len(ports) != 1 || ports["1.2.3.4"] != 1915 {
		t.Fatalf("ports %v", ports)
	}
	tcp := &Node{ID: "1.2.3.4-tcp1605", IP: "1.2.3.4", Port: 1605, Proto: "tcp", Kind: "residential",
		Config: "client\nproto tcp\nremote 1.2.3.4 1605\n<ca>x</ca>\n"}
	other := &Node{ID: "5.6.7.8-tcp443", IP: "5.6.7.8", Port: 443, Proto: "tcp"}
	out := WithUDP([]*Node{tcp, other}, ports)
	if len(out) != 3 {
		t.Fatalf("want one UDP variant added, got %d nodes", len(out))
	}
	u := out[2]
	if u.ID != "1.2.3.4-udp1915" || u.Proto != "udp" || u.Port != 1915 || u.Kind != "residential" ||
		!strings.Contains(u.Config, "proto udp\nremote 1.2.3.4 1915\n<ca>") || tcp.Proto != "tcp" {
		t.Errorf("bad variant %+v\n%s", u, u.Config)
	}
	if len(WithUDP(out, ports)) != 3 {
		t.Error("variants must not be duplicated")
	}
}

func TestResolverServesStaleInstantly(t *testing.T) {
	r := NewResolver([]string{"127.0.0.1"})
	want := []net.IP{net.ParseIP("203.0.113.5")}
	r.cache["stale.test"] = dnsEntry{want, time.Now().Add(-10 * time.Minute)}
	start := time.Now()
	got, err := r.Resolve(context.Background(), "stale.test", "")
	if err != nil || !got[0].Equal(want[0]) || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("stale entry not served instantly: %v %v %v", got, err, time.Since(start))
	}
	r.mu.Lock()
	refreshing := r.inflight["stale.test"] != nil || r.cache["stale.test"].fetched.After(start)
	r.mu.Unlock()
	if !refreshing {
		t.Error("stale entry should trigger a background refresh")
	}
}

func TestRealtimeSwitching(t *testing.T) {
	t.Setenv("WEB_PASS", "x")
	t.Setenv("SS_PASSWORD", "y")
	t.Setenv("DATA_DIR", t.TempDir())
	cfg, _ := LoadConfig()
	alive := func(id string, loss ...float64) *Tunnel {
		tun := &Tunnel{Node: &Node{ID: id, IP: id}, exited: make(chan struct{}), Live: LiveStats{Loss: loss}}
		return tun
	}
	rounds := func(v float64) []float64 { return []float64{v, v, v, v, v, v} }
	cases := []struct {
		name          string
		active, stdby []float64
		pinned, want  bool
	}{
		{"clean active stays", rounds(0), rounds(0), false, false},
		{"lossy active, clean standby -> switch", rounds(20), rounds(0), false, true},
		{"too few rounds -> wait", []float64{40, 40}, rounds(0), false, false},
		{"standby not clearly better -> stay", rounds(8), rounds(5), false, false},
		{"pinned lossy node stays", rounds(20), rounds(0), true, false},
		{"dead active -> switch even without history", []float64{100, 100, 100}, []float64{0}, false, true},
	}
	for _, c := range cases {
		m := NewManager(cfg)
		a, s := alive("a", c.active...), alive("s", c.stdby...)
		m.active, m.standby = a, s
		if c.pinned {
			m.lockedID = "a"
		}
		m.decide()
		if switched := m.active == s; switched != c.want {
			t.Errorf("%s: switched=%v", c.name, switched)
		}
	}
	// A lossy standby is dropped so a clean one gets acquired.
	m := NewManager(cfg)
	m.active, m.standby = alive("a", rounds(0)...), alive("s", rounds(30)...)
	m.decide()
	if m.standby != nil {
		t.Error("lossy standby should be released")
	}
}

func TestConfig(t *testing.T) {
	t.Setenv("WEB_PASS", "x")
	t.Setenv("SS_PASSWORD", "y")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.Transport != "udp" {
		t.Errorf("default transport %q", c.Transport)
	}
	if c.WebPort != 54345 || c.SSPort != 7929 || c.Countries[0] != "JP" || !c.ResidentialOnly || !c.Standby {
		t.Errorf("unexpected defaults %+v", c)
	}
	t.Setenv("SS_ALLOW", "203.0.113.0/24, 198.51.100.7")
	t.Setenv("COUNTRIES", "jp,kr")
	t.Setenv("WEB_PORT", "99999")
	c, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SSAllow) != 2 || c.Countries[1] != "KR" || c.WebPort != 65535 {
		t.Errorf("env parsing: %+v", c)
	}
	t.Setenv("WEB_PASS", "")
	if _, err := LoadConfig(); err == nil {
		t.Error("empty WEB_PASS must be rejected")
	}
}

func TestSetEnv(t *testing.T) {
	got := setEnv("A=1\nWEB_PASS=old\n# WEB_PASS=x\n", "WEB_PASS", "new$1")
	if got != "A=1\nWEB_PASS=new$1\n# WEB_PASS=x\n" {
		t.Errorf("got %q", got)
	}
	if s := randomString(20); len(s) != 20 {
		t.Error("bad random length")
	}
}
