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

	WebHost string
	WebPort int
	WebUser string
	WebPass string

	// Shadowsocks: the single client entry, encrypted, TCP + UDP on one port
	SSHost     string
	SSPort     int
	SSPassword string
	SSMethod   string
	SSAllow    []*net.IPNet // allowed client sources; empty = everyone
	SSMaxConns int

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

	ProbeTarget     string
	MonitorInterval time.Duration
	FailLossPct     float64

	DNSServers []string
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
		Sources:          list("SOURCES", "https://www.vpngate.net/api/iphone/,http://www.vpngate.net/api/iphone/"),
		Countries:        list("COUNTRIES", "JP"),
		Transport:        strings.ToLower(str("TRANSPORT", "udp")),
		ResidentialOnly:  boolEnv("RESIDENTIAL_ONLY", true),
		DeepTestCount:    num("DEEP_TEST_COUNT", 6, 1, 30),
		DeepTestParallel: num("DEEP_TEST_PARALLEL", 3, 1, 10),
		SpeedtestBytes:   int64(num("SPEEDTEST_BYTES", 10_000_000, 0, 100_000_000)),
		Standby:          boolEnv("STANDBY", true),
		Refresh:          time.Duration(num("REFRESH_MINUTES", 30, 5, 1440)) * time.Minute,
		Hold:             time.Duration(num("HOLD_MINUTES", 90, 5, 10080)) * time.Minute,
		MinMbps:          float64(num("MIN_MBPS", 50, 0, 10000)),
		ProbeTarget:      str("PROBE_TARGET", "1.1.1.1"),
		MonitorInterval:  time.Duration(num("MONITOR_INTERVAL", 2, 1, 60)) * time.Second,
		FailLossPct:      float64(num("FAIL_LOSS_PCT", 5, 1, 100)),
		DNSServers:       list("DNS_SERVERS", "1.1.1.1,8.8.8.8"),
	}
	for i, cc := range c.Countries {
		c.Countries[i] = strings.ToUpper(cc)
	}
	for _, item := range list("SS_ALLOW", "") {
		if !strings.Contains(item, "/") {
			if strings.Contains(item, ":") {
				item += "/128"
			} else {
				item += "/32"
			}
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("SS_ALLOW 格式错误 %q: %v", item, err)
		}
		c.SSAllow = append(c.SSAllow, network)
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
	if c.Transport != "udp" && c.Transport != "tcp" && c.Transport != "auto" {
		return nil, fmt.Errorf("TRANSPORT 只能是 udp / tcp / auto")
	}
	if net.ParseIP(c.ProbeTarget).To4() == nil {
		return nil, fmt.Errorf("PROBE_TARGET 必须是 IPv4 地址")
	}
	return c, nil
}

func (c *Config) RunDir() string { return c.DataDir + "/run" }

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
