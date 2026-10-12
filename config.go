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

	ProxyHost     string
	ProxyPort     int
	ProxyUser     string
	ProxyPass     string
	ProxyAllow    []*net.IPNet
	ProxyMaxConns int
	FastConnect   bool

	Sources          []string
	Countries        []string
	ResidentialOnly  bool
	TCPPenaltyMs     float64
	DeepTestCount    int
	DeepTestParallel int
	SpeedtestBytes   int64
	Standby          bool
	AutoUpgrade      bool
	Refresh          time.Duration

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
		ProxyHost:        str("PROXY_HOST", "0.0.0.0"),
		ProxyPort:        num("PROXY_PORT", 7928, 1, 65535),
		ProxyUser:        str("PROXY_USER", ""),
		ProxyPass:        str("PROXY_PASS", ""),
		ProxyMaxConns:    num("PROXY_MAX_CONNS", 8192, 16, 1<<20),
		FastConnect:      boolEnv("FAST_CONNECT", true),
		Sources:          list("SOURCES", "https://www.vpngate.net/api/iphone/,http://www.vpngate.net/api/iphone/"),
		Countries:        list("COUNTRIES", "JP"),
		ResidentialOnly:  boolEnv("RESIDENTIAL_ONLY", true),
		TCPPenaltyMs:     float64(num("TCP_PENALTY_MS", 15, 0, 1000)),
		DeepTestCount:    num("DEEP_TEST_COUNT", 6, 1, 30),
		DeepTestParallel: num("DEEP_TEST_PARALLEL", 3, 1, 10),
		SpeedtestBytes:   int64(num("SPEEDTEST_BYTES", 2_000_000, 0, 100_000_000)),
		Standby:          boolEnv("STANDBY", true),
		AutoUpgrade:      boolEnv("AUTO_UPGRADE", false),
		Refresh:          time.Duration(num("REFRESH_MINUTES", 30, 5, 1440)) * time.Minute,
		ProbeTarget:      str("PROBE_TARGET", "1.1.1.1"),
		MonitorInterval:  time.Duration(num("MONITOR_INTERVAL", 5, 1, 60)) * time.Second,
		FailLossPct:      float64(num("FAIL_LOSS_PCT", 30, 1, 100)),
		DNSServers:       list("DNS_SERVERS", "1.1.1.1,8.8.8.8"),
	}
	for i, cc := range c.Countries {
		c.Countries[i] = strings.ToUpper(cc)
	}
	for _, item := range list("PROXY_ALLOW", "") {
		if !strings.Contains(item, "/") {
			if strings.Contains(item, ":") {
				item += "/128"
			} else {
				item += "/32"
			}
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("PROXY_ALLOW 格式错误 %q: %v", item, err)
		}
		c.ProxyAllow = append(c.ProxyAllow, network)
	}
	if c.WebPass == "" {
		return nil, fmt.Errorf("WEB_PASS 未设置，拒绝以空密码启动管理后台")
	}
	if c.WebPort == c.ProxyPort {
		return nil, fmt.Errorf("PROXY_PORT 与 WEB_PORT 不能相同")
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
