// VPNGATE: VPNGate Japanese residential exit gateway with an HTTP / SOCKS5 proxy.
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Set at build time: -ldflags "-X main.version=1.0.0 -X main.repo=owner/vpngate"
var (
	version = "dev"
	repo    = "GHUNLIL/vpngate"
)

const (
	binPath  = "/usr/local/bin/vpngate"
	envPath  = "/etc/vpngate/vpngate.env"
	unitPath = "/etc/systemd/system/vpngate.service"
	sysctl   = "/etc/sysctl.d/98-vpngate.conf"
)

var (
	//go:embed deploy/vpngate.env.example
	envTemplate string
	//go:embed deploy/vpngate.service
	unitFile string
	//go:embed deploy/98-vpngate.conf
	sysctlFile string
)

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "run":
		err = run()
	case "install":
		err = install()
	case "uninstall":
		err = uninstall()
	case "info":
		err = info()
	case "passwd":
		err = passwd()
	case "config":
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		if err = shell(editor, envPath); err == nil {
			err = shell("systemctl", "restart", "vpngate")
		}
	case "update":
		err = shell("bash", "-c", fmt.Sprintf("curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | bash", repo))
	case "status", "start", "stop", "restart":
		err = shell("systemctl", cmd, "vpngate", "--no-pager")
	case "logs":
		err = shell("journalctl", "-u", "vpngate", "-f", "-n", "100")
	case "version":
		fmt.Println("vpngate", version)
	default:
		fmt.Print(`用法: vpngate <命令>
  info       显示后台地址、账号和代理连接串
  status     服务状态          logs     实时日志
  restart    重启 (start / stop 同理)
  config     编辑配置并重启    passwd   重新生成后台和代理密码
  update     从 GitHub 更新    uninstall 卸载
  run        前台运行 (systemd 使用)
  version    版本
`)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- daemon

// LogRing keeps the most recent log lines for the web UI.
type LogRing struct {
	mu    sync.Mutex
	lines []string
}

func (l *LogRing) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		l.lines = append(l.lines, line)
	}
	if len(l.lines) > 300 {
		l.lines = append([]string(nil), l.lines[len(l.lines)-300:]...)
	}
	return len(p), nil
}

func (l *LogRing) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func run() error {
	ring := &LogRing{}
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(io.MultiWriter(os.Stdout, ring))

	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		log.Printf("警告: 未以 root 运行，OpenVPN、策略路由和 ICMP 检测将无法工作")
	}
	log.Printf("VPNGATE %s 启动，目标国家 %s，仅家宽=%v", version, strings.Join(cfg.Countries, ","), cfg.ResidentialOnly)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m := NewManager(cfg)
	p := &Proxy{Addr: net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort)), User: cfg.ProxyUser,
		Pass: cfg.ProxyPass, Allow: cfg.ProxyAllow, MaxConns: int64(cfg.ProxyMaxConns), FastConnect: cfg.FastConnect,
		Dial: TunnelDialer(m.res, m.Route)}
	if err := p.Listen(); err != nil {
		return err
	}
	defer p.Close()
	go func() { _ = p.Serve() }()

	web := NewWebUI(cfg, m, p, ring)
	webAddr := net.JoinHostPort(cfg.WebHost, strconv.Itoa(cfg.WebPort))
	errc := make(chan error, 1)
	go func() { errc <- web.Serve(ctx, webAddr) }()
	log.Printf("管理后台已监听 %s", webAddr)

	if err := m.Start(ctx); err != nil {
		return err
	}
	go m.Run(ctx)

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	log.Printf("正在关闭隧道...")
	m.Shutdown()
	return err
}

// ---------------------------------------------------------------- management

func install() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("请使用 root 运行")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, _ = filepath.EvalSymlinks(self); self != binPath {
		if err := copyFile(self, binPath, 0o755); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/etc/vpngate", "/var/lib/vpngate"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		env := setEnv(envTemplate, "WEB_PASS", randomString(20))
		env = setEnv(env, "PROXY_USER", "u"+randomString(7))
		env = setEnv(env, "PROXY_PASS", randomString(20))
		if err := os.WriteFile(envPath, []byte(env), 0o600); err != nil {
			return err
		}
		fmt.Println("已生成配置", envPath)
	} else {
		fmt.Println("保留现有配置", envPath)
	}
	_ = exec.Command("modprobe", "tcp_bbr").Run()
	if err := os.WriteFile(sysctl, []byte(sysctlFile), 0o644); err != nil {
		return err
	}
	_ = exec.Command("sysctl", "-q", "--system").Run() // re-apply all files so host tuning keeps precedence
	if out, _ := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output(); strings.TrimSpace(string(out)) != "bbr" {
		fmt.Println("提示: 内核不支持 BBR (需要 4.9+)，其他网络优化已生效")
	}
	if err := os.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "vpngate"}, {"restart", "vpngate"}} {
		if err := exec.Command("systemctl", args...).Run(); err != nil {
			return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
		}
	}
	fmt.Println("安装完成")
	return info()
}

func uninstall() error {
	fmt.Print("确定卸载 VPNGATE? 配置和数据也会删除 [y/N] ")
	var answer string
	_, _ = fmt.Scanln(&answer)
	if answer != "y" && answer != "Y" {
		return nil
	}
	_ = exec.Command("systemctl", "disable", "--now", "vpngate").Run()
	for _, p := range []string{unitPath, sysctl, "/etc/vpngate", "/var/lib/vpngate", binPath} {
		_ = os.RemoveAll(p)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("已卸载")
	return nil
}

func info() error {
	env, err := readEnv()
	if err != nil {
		return err
	}
	ip := publicIP()
	user, pass, port := env["PROXY_USER"], env["PROXY_PASS"], env["PROXY_PORT"]
	state, _ := exec.Command("systemctl", "is-active", "vpngate").Output()
	fmt.Printf(`
  管理后台  http://%s:%s/
  后台账号  %s / %s

  SOCKS5   socks5h://%s:%s@%s:%s
  HTTP     http://%s:%s@%s:%s

  经专线中转时，把 %s:%s 换成专线入口地址。
  服务状态  %s
`, ip, env["WEB_PORT"], env["WEB_USER"], env["WEB_PASS"], user, pass, ip, port, user, pass, ip, port, ip, port,
		strings.TrimSpace(string(state)))
	return nil
}

func passwd() error {
	data, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	env := setEnv(string(data), "WEB_PASS", randomString(20))
	env = setEnv(env, "PROXY_PASS", randomString(20))
	if err := os.WriteFile(envPath, []byte(env), 0o600); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "restart", "vpngate").Run(); err != nil {
		return err
	}
	return info()
}

func readEnv() (map[string]string, error) {
	data, err := os.ReadFile(envPath)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = v
		}
	}
	return env, nil
}

func setEnv(text, key, value string) string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `=.*$`)
	return re.ReplaceAllLiteralString(text, key+"="+value)
}

func publicIP() string {
	client := &http.Client{Timeout: 4 * time.Second}
	if resp, err := client.Get("https://api.ipify.org"); err == nil {
		defer resp.Body.Close()
		if b, err := io.ReadAll(io.LimitReader(resp.Body, 64)); err == nil && net.ParseIP(string(b)) != nil {
			return string(b)
		}
	}
	return "服务器IP"
}

func randomString(n int) string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	for len(out) < n {
		_, _ = rand.Read(buf)
		if int(buf[0]) < 256/len(chars)*len(chars) { // reject to avoid modulo bias
			out = append(out, chars[int(buf[0])%len(chars)])
		}
	}
	return string(out)
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst) // atomic: safe while the old binary is running
}

func shell(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}
