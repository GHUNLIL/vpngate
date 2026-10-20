package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read once from the environment (systemd EnvironmentFile=/etc/vpngate/vpngate.env).
type Config struct {
	DataDir string
	OpenVPN string

	WebHost  string
	WebPort  int
	WebUser  string
	WebPass  string
	WebAllow []*net.IPNet // allowed admin sources; empty = everyone

	// Shadowsocks: the single client entry, encrypted, TCP + UDP on one port
	SSHost     string
	SSPort     int
	SSPassword string
	SSMethod   string
	SSAllow    []*net.IPNet // allowed client sources; empty = everyone
	SSMaxConns int

	// Exit pool: EXITS sticky tunnels, each with a fixed exit IP behind its own SOCKS5 port
	Exits       int
	ExitHost    string
	ExitPort    int // first port; exit i listens on ExitPort+i
	ExitUser    string
	ExitPass    string
	ExitAllow   []*net.IPNet // allowed client sources; empty = everyone
	ExitMaxLoss float64      // replace an exit whose loss over the last ~30 s exceeds this (%)

	Sources          []string
	Transport        string // udp (native UDP only, TCP as last resort) | tcp | auto
	Countries        []string
	ResidentialOnly  bool
	DeepTestCount    int
	DeepTestParallel int
	SpeedtestBytes   int64
	Standby          bool
	Refresh          time.Duration
	Hold             time.Duration // keep the exit IP this long, then re-select the best node
	MinMbps          float64       // speed bar; among nodes reaching it the lowest latency wins
	NoRepeat         bool          // rotation mode: every hold moves to an exit IP not used before

	ConnectTestURL   string // real request through each candidate tunnel; empty = off
	ConnectTestCount int

	ProbeTarget     string
	MonitorInterval time.Duration
	FailLossPct     float64

	DNSServers []string

	NotifyWebhook string // POST JSON on exit IP change / outage / recovery
	TGBotToken    string
	TGChatID      string
}

func LoadConfig() (*Config, error) {
	c := &Config{
		DataDir:          str("DATA_DIR", "/var/lib/vpngate"),
		OpenVPN:          str("OPENVPN", "openvpn"),
		WebHost:          str("WEB_HOST", "0.0.0.0"),
		WebPort:          num("WEB_PORT", 54345, 1, 65535),
		WebUser:          str("WEB_USER", "admin"),
		WebPass:          str("WEB_PASS", ""),
		SSHost:           str("SS_HOST", "0.0.0.0"),
		SSPort:           num("SS_PORT", 7929, 1, 65535),
		SSPassword:       str("SS_PASSWORD", ""),
		SSMethod:         str("SS_METHOD", "aes-128-gcm"),
		SSMaxConns:       num("SS_MAX_CONNS", 8192, 16, 1<<20),
		Exits:            num("EXITS", 0, 0, 16),
		ExitHost:         str("EXIT_HOST", "127.0.0.1"),
		ExitPort:         num("EXIT_PORT", 10801, 1, 65535),
		ExitUser:         str("EXIT_USER", "vpngate"),
		ExitPass:         str("EXIT_PASS", ""),
		ExitMaxLoss:      float64(num("EXIT_MAX_LOSS", 20, 1, 100)),
		Sources:          list("SOURCES", "https://www.vpngate.net/api/iphone/,http://www.vpngate.net/api/iphone/"),
		Countries:        list("COUNTRIES", "JP"),
		Transport:        strings.ToLower(str("TRANSPORT", "udp")),
		ResidentialOnly:  boolEnv("RESIDENTIAL_ONLY", true),
		DeepTestCount:    num("DEEP_TEST_COUNT", 6, 1, 30),
		DeepTestParallel: num("DEEP_TEST_PARALLEL", 3, 1, 10),
		SpeedtestBytes:   int64(num("SPEEDTEST_BYTES", 4_000_000, 0, 100_000_000)),
		Standby:          boolEnv("STANDBY", true),
		Refresh:          time.Duration(num("REFRESH_MINUTES", 30, 5, 1440)) * time.Minute,
		Hold:             time.Duration(num("HOLD_MINUTES", 90, 1, 10080)) * time.Minute,
		MinMbps:          float64(num("MIN_MBPS", 50, 0, 10000)),
		NoRepeat:         boolEnv("ROTATE_NO_REPEAT", false),
		ConnectTestURL:   str("CONNECT_TEST_URL", ""),
		ConnectTestCount: num("CONNECT_TEST_COUNT", 3, 1, 10),
		ProbeTarget:      str("PROBE_TARGET", "1.1.1.1"),
		MonitorInterval:  time.Duration(num("MONITOR_INTERVAL", 2, 1, 60)) * time.Second,
		FailLossPct:      float64(num("FAIL_LOSS_PCT", 5, 1, 100)),
		DNSServers:       list("DNS_SERVERS", "1.1.1.1,8.8.8.8"),
		NotifyWebhook:    str("NOTIFY_WEBHOOK", ""),
		TGBotToken:       str("TG_BOT_TOKEN", ""),
		TGChatID:         str("TG_CHAT_ID", ""),
	}
	for i, cc := range c.Countries {
		c.Countries[i] = strings.ToUpper(cc)
	}
	var err error
	if c.SSAllow, err = cidrList("SS_ALLOW"); err != nil {
		return nil, err
	}
	if c.WebAllow, err = cidrList("WEB_ALLOW"); err != nil {
		return nil, err
	}
	if c.ExitAllow, err = cidrList("EXIT_ALLOW"); err != nil {
		return nil, err
	}
	if c.WebPass == "" {
		return nil, fmt.Errorf("WEB_PASS 未设置，拒绝以空密码启动管理后台")
	}
	if c.SSPassword == "" {
		return nil, fmt.Errorf("SS_PASSWORD 未设置")
	}
	if c.WebPort == c.SSPort {
		return nil, fmt.Errorf("WEB_PORT 与 SS_PORT 不能相同")
	}
	if c.Exits > 0 {
		if c.ExitPass == "" {
			return nil, fmt.Errorf("EXITS 已开启但 EXIT_PASS 未设置")
		}
		if c.ExitPort+c.Exits-1 > 65535 {
			return nil, fmt.Errorf("EXIT_PORT + EXITS 超出端口范围")
		}
		for _, p := range []int{c.WebPort, c.SSPort} {
			if p >= c.ExitPort && p < c.ExitPort+c.Exits {
				return nil, fmt.Errorf("出口端口 %d-%d 与 WEB_PORT / SS_PORT 冲突", c.ExitPort, c.ExitPort+c.Exits-1)
			}
		}
	}
	if c.Transport != "udp" && c.Transport != "tcp" && c.Transport != "auto" {
		return nil, fmt.Errorf("TRANSPORT 只能是 udp / tcp / auto")
	}
	if u := c.ConnectTestURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return nil, fmt.Errorf("CONNECT_TEST_URL 必须以 http:// 或 https:// 开头")
	}
	if net.ParseIP(c.ProbeTarget).To4() == nil {
		return nil, fmt.Errorf("PROBE_TARGET 必须是 IPv4 地址")
	}
	return c, nil
}

func (c *Config) RunDir() string { return c.DataDir + "/run" }

// cidrList parses a comma-separated list of IPs / CIDRs from the environment.
func cidrList(name string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range list(name, "") {
		if !strings.Contains(item, "/") {
			if strings.Contains(item, ":") {
				item += "/128"
			} else {
				item += "/32"
			}
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("%s 格式错误 %q: %v", name, item, err)
		}
		out = append(out, network)
	}
	return out, nil
}

func str(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func num(name string, def, lo, hi int) int {
	v, err := strconv.Atoi(str(name, ""))
	if err != nil {
		return def
	}
	return min(hi, max(lo, v))
}

func boolEnv(name string, def bool) bool {
	switch strings.ToLower(str(name, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func list(name, def string) []string {
	var out []string
	for _, item := range strings.Split(str(name, def), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
