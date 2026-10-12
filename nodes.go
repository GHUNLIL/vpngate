package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const userAgent = "Mozilla/5.0 (VPNGATE node manager)"

var (
	// University of Tsukuba relay servers: fast, but academic, not home broadband.
	academicNet  = mustCIDR("219.100.37.0/24")
	datacenterRE = regexp.MustCompile(`(?i)\b(cloud|colo(cation)?|data ?cent(er|re)|hosting|server|vps|idc|amazon|` +
		`google|microsoft|azure|oracle|linode|akamai|vultr|digitalocean|ovh|hetzner|sakura|conoha|xserver|` +
		`idcf|kagoya|softether)\b`)
)

// Node is one VPNGate server plus everything we measured about it.
type Node struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Proto      string `json:"proto"`
	HostName   string `json:"host_name"`
	Country    string `json:"country"`
	VGPing     int    `json:"vg_ping"`
	VGSpeed    int64  `json:"vg_speed"`
	VGSessions int    `json:"vg_sessions"`
	Operator   string `json:"operator"`
	Config     string `json:"config,omitempty"`

	Kind string `json:"kind"` // residential | mobile | hosting | academic | unknown
	ISP  string `json:"isp"`
	City string `json:"city"`

	DirectRTT   *float64 `json:"direct_rtt"` // stage 1: VPS -> node
	HandshakeMs *float64 `json:"handshake_ms"`
	RTT         *float64 `json:"rtt"` // stage 2: through the tunnel
	Jitter      *float64 `json:"jitter"`
	Loss        *float64 `json:"loss"`
	Mbps        *float64 `json:"mbps"`
	ExitIP      string   `json:"exit_ip"`
	TestedAt    int64    `json:"tested_at"`
	Error       string   `json:"error"`
	FailedUntil int64    `json:"failed_until"`
}

// Score: lower is better. Latency dominates, jitter and loss weigh heavily, UDP preferred.
func (n *Node) Score(tcpPenalty float64) float64 {
	if n.RTT == nil {
		return math.Inf(1)
	}
	s := *n.RTT + 2*val(n.Jitter) + 15*val(n.Loss) - 0.3*math.Min(val(n.Mbps), 100)
	if n.Proto == "tcp" {
		s += tcpPenalty
	}
	return s
}

func (n *Node) PrefilterKey(tcpPenalty float64) float64 {
	k := 200 + float64(n.VGPing)
	if n.DirectRTT != nil {
		k = *n.DirectRTT
	}
	if n.Proto == "tcp" {
		k += tcpPenalty
	}
	return k
}

func (n *Node) Failed(now time.Time) bool { return n.FailedUntil > now.Unix() }

func val(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func ptr(v float64) *float64 { return &v }

// ---------------------------------------------------------------- fetch & parse

func FetchCSV(ctx context.Context, sources []string, cacheFile string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	for _, url := range sources {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("节点源 %s 获取失败: %v", url, err)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err == nil && bytes.HasPrefix(data, []byte("*vpn_servers")) && bytes.Count(data, []byte("\n")) > 3 {
			_ = os.WriteFile(cacheFile, data, 0o600)
			log.Printf("节点列表已从 %s 获取", url)
			return data, nil
		}
		log.Printf("节点源 %s 返回了无效内容", url)
	}
	if data, err := os.ReadFile(cacheFile); err == nil {
		log.Printf("所有节点源不可用，使用本地缓存")
		return data, nil
	}
	return nil, errors.New("无法获取 VPNGate 节点列表，且没有本地缓存")
}

func ParseRemote(config, fallbackIP string) (proto, host string, port int) {
	proto, host, port = "udp", fallbackIP, 1194
	for _, line := range strings.Split(config, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 2 && f[0] == "proto":
			proto = "udp"
			if strings.HasPrefix(f[1], "tcp") {
				proto = "tcp"
			}
		case len(f) >= 3 && f[0] == "remote":
			if p, err := strconv.Atoi(f[2]); err == nil {
				host, port = f[1], p
			}
		}
	}
	return
}

func ParseCSV(data []byte, countries []string) []*Node {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" && !strings.HasPrefix(line, "*") {
			lines = append(lines, strings.TrimPrefix(line, "#"))
		}
	}
	r := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	want := map[string]bool{}
	for _, c := range countries {
		want[c] = true
	}
	seen := map[string]bool{}
	var nodes []*Node
	for _, row := range rows[1:] {
		country := strings.ToUpper(get(row, "CountryShort"))
		if len(want) > 0 && !want[country] {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(get(row, "OpenVPN_ConfigData_Base64"))
		if err != nil {
			continue
		}
		config := string(raw)
		proto, host, port := ParseRemote(config, get(row, "IP"))
		if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
			continue
		}
		id := fmt.Sprintf("%s-%s%d", host, proto, port)
		if seen[id] {
			continue
		}
		seen[id] = true
		ping, _ := strconv.Atoi(get(row, "Ping"))
		speed, _ := strconv.ParseInt(get(row, "Speed"), 10, 64)
		sessions, _ := strconv.Atoi(get(row, "NumVpnSessions"))
		nodes = append(nodes, &Node{
			ID: id, IP: host, Port: port, Proto: proto, HostName: get(row, "HostName"), Country: country,
			VGPing: ping, VGSpeed: speed, VGSessions: sessions, Operator: get(row, "Operator"),
			Config: config, Kind: "unknown",
		})
	}
	return nodes
}

// ---------------------------------------------------------------- classification

type ipInfo struct {
	Status  string `json:"status"`
	Query   string `json:"query"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	City    string `json:"city"`
	Mobile  bool   `json:"mobile"`
	Hosting bool   `json:"hosting"`
	At      int64  `json:"at"`
}

func Classify(info ipInfo, n *Node) string {
	if strings.Contains(strings.ToLower(n.Operator), "academic use only") || academicNet.Contains(net.ParseIP(n.IP)) {
		return "academic"
	}
	if info.Status != "success" {
		return "unknown"
	}
	if info.Mobile {
		return "mobile"
	}
	if info.Hosting || datacenterRE.MatchString(info.ISP+" "+info.Org+" "+info.AS) {
		return "hosting"
	}
	return "residential"
}

// ClassifyNodes annotates nodes with ISP / city / kind via ip-api.com batch lookups, cached for a week.
func ClassifyNodes(ctx context.Context, nodes []*Node, cacheFile string) {
	cache := map[string]ipInfo{}
	if data, err := os.ReadFile(cacheFile); err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	now := time.Now().Unix()
	var missing []string
	for _, n := range nodes {
		if now-cache[n.IP].At > 7*86400 {
			missing = append(missing, n.IP)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < len(missing); i += 100 {
		batch, _ := json.Marshal(missing[i:min(i+100, len(missing))])
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://ip-api.com/batch?fields=status,query,isp,org,as,city,mobile,hosting", bytes.NewReader(batch))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("IP 归属查询失败 (仅按本地规则分类): %v", err)
			break
		}
		var items []ipInfo
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil {
			break
		}
		for _, item := range items {
			item.At = now
			cache[item.Query] = item
		}
	}
	for _, n := range nodes {
		info := cache[n.IP]
		n.Kind = Classify(info, n)
		n.ISP = info.ISP
		if n.ISP == "" {
			n.ISP = info.Org
		}
		n.City = info.City
	}
	if data, err := json.Marshal(cache); err == nil {
		_ = os.WriteFile(cacheFile, data, 0o600)
	}
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}
