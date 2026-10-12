package main

// OpenVPN tunnel lifecycle and per-device policy routing.
//
// Every tunnel gets its own device (vgN) and routing table (1000+N) with an "oif" rule, so sockets
// bound to the device egress through it while the VPS's main routing table is untouched. That lets
// the active tunnel, a warm standby and test tunnels run side by side.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxSlots  = 32
	tableBase = 1000
)

// Lines that mean the handshake failed for good. Note "Options error ... [PUSH-OPTIONS]" is only a
// warning about a pushed option we filtered, so it must not count.
var fatalMarkers = []string{"auth_failed", "authentication failed", "exiting due to fatal error",
	"cannot open tun", "cannot ioctl"}

// Lines too generic to explain a failure on their own.
var noiseMarkers = []string{"exiting due to fatal error", "sigterm", "sigusr1", "process exiting",
	"restart pause", "closing tun", "ifconfig_pool"}

type Tunnel struct {
	Node      *Node
	Slot      int
	Dev       string
	Table     int
	Probe     string // health-check method: "icmp", or "tcp" for nodes that drop ICMP
	StartedAt time.Time

	conf   string
	cmd    *exec.Cmd
	exited chan struct{}
	mu     sync.Mutex
	recent []string // last informative output lines, for error messages
}

func NewTunnel(n *Node, slot int, runDir string) *Tunnel {
	dev := "vg" + strconv.Itoa(slot)
	return &Tunnel{Node: n, Slot: slot, Dev: dev, Table: tableBase + slot, Probe: "icmp",
		conf: filepath.Join(runDir, dev+".ovpn")}
}

func OpenVPNArgs(conf, auth, dev, proto string, version [2]int) []string {
	args := []string{
		"--config", conf,
		"--dev", dev, "--dev-type", "tun", "--txqueuelen", "1000",
		"--route-nopull", // never touch the VPS's own routes
		"--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6",
		"--pull-filter", "ignore", "ping-restart", "--pull-filter", "ignore", "redirect-gateway",
		"--pull-filter", "ignore", "dhcp-option", "--pull-filter", "ignore", "block-outside-dns",
		"--auth-user-pass", auth, "--auth-nocache",
		"--remote-cert-tls", "server",
		"--resolv-retry", "0", "--connect-retry-max", "1", "--connect-timeout", "10",
		// Fail fast instead of silently reconnecting: the manager fails over to the standby.
		"--ping", "5", "--ping-exit", "25",
		// Japanese home lines are often PPPoE (MTU 1454); keep encapsulated packets under it.
		"--mssfix", "1360",
		"--verb", "3", "--mute-replay-warnings", "--suppress-timestamps",
	}
	if version[0] > 2 || version[0] == 2 && version[1] >= 5 {
		args = append(args, "--data-ciphers", "AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305:AES-128-CBC",
			"--data-ciphers-fallback", "AES-128-CBC")
	}
	if proto == "udp" {
		args = append(args, "--fast-io", "--sndbuf", "4194304", "--rcvbuf", "4194304")
	}
	if st, err := os.Stat("/etc/ssl/certs"); err == nil && st.IsDir() {
		args = append(args, "--capath", "/etc/ssl/certs")
	}
	return args
}

func OpenVPNVersion(binary string) ([2]int, error) {
	out, _ := exec.Command(binary, "--version").CombinedOutput()
	m := regexp.MustCompile(`OpenVPN (\d+)\.(\d+)`).FindSubmatch(out)
	if m == nil {
		return [2]int{}, fmt.Errorf("找不到可用的 OpenVPN: %s", binary)
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	return [2]int{major, minor}, nil
}

// Start brings the tunnel up and installs its routing; returns the handshake time in ms.
func (t *Tunnel) Start(ctx context.Context, binary, auth string, version [2]int, timeout time.Duration) (float64, error) {
	if err := os.WriteFile(t.conf, []byte(t.Node.Config), 0o600); err != nil {
		return 0, err
	}
	start := time.Now()
	cmd := exec.Command(binary, OpenVPNArgs(t.conf, auth, t.Dev, t.Node.Proto, version)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("OpenVPN 启动失败: %w", err)
	}
	t.cmd = cmd
	t.exited = make(chan struct{})
	ready := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(out)
		signalled := false
		for sc.Scan() {
			line := sc.Text()
			lower := strings.ToLower(line)
			if !containsAny(lower, noiseMarkers) {
				t.mu.Lock()
				t.recent = append(t.recent, line)
				if len(t.recent) > 8 {
					t.recent = t.recent[1:]
				}
				t.mu.Unlock()
			}
			switch {
			case !signalled && strings.Contains(lower, "initialization sequence completed"):
				ready <- nil
				signalled = true
			case !signalled && containsAny(lower, fatalMarkers):
				ready <- errors.New(t.LastLog())
				signalled = true
			case signalled && containsAny(lower, []string{"error", "restart", "exiting"}):
				log.Printf("[%s] %s", t.Dev, line)
			}
		}
		_ = cmd.Wait()
		if !signalled {
			ready <- fmt.Errorf("OpenVPN 已退出: %s", t.LastLog())
		}
		close(t.exited)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err = <-ready:
	case <-timer.C:
		err = fmt.Errorf("握手超时 (%s)", timeout)
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err == nil {
		err = t.setupRouting()
	}
	if err != nil {
		t.Stop()
		return 0, err
	}
	t.StartedAt = time.Now()
	return float64(time.Since(start).Milliseconds()), nil
}

func (t *Tunnel) Alive() bool {
	if t.exited == nil {
		return false
	}
	select {
	case <-t.exited:
		return false
	default:
		return true
	}
}

// LastLog returns the most recent informative OpenVPN line (the cause, not "exiting").
func (t *Tunnel) LastLog() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.recent) == 0 {
		return "无输出"
	}
	return tail(t.recent[len(t.recent)-1], 160)
}

func (t *Tunnel) setupRouting() error {
	table, prio := strconv.Itoa(t.Table), strconv.Itoa(t.Table)
	_ = ipCmd("rule", "del", "priority", prio)
	if err := ipCmd("route", "replace", "default", "dev", t.Dev, "table", table); err != nil {
		return err
	}
	if err := ipCmd("rule", "add", "oif", t.Dev, "lookup", table, "priority", prio); err != nil {
		return err
	}
	// Loose reverse-path filtering on our device only; the kernel uses max(all, dev).
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+t.Dev+"/rp_filter", []byte("2"), 0o644)
	return nil
}

func (t *Tunnel) Stop() {
	if t.cmd != nil && t.Alive() {
		_ = syscall.Kill(-t.cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-t.exited:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL)
			<-t.exited
		}
	}
	cleanupTable(t.Table)
	_ = os.Remove(t.conf)
}

func cleanupTable(table int) {
	_ = ipCmd("rule", "del", "priority", strconv.Itoa(table))
	_ = ipCmd("route", "flush", "table", strconv.Itoa(table))
}

// CleanupStale kills OpenVPN processes and routing rules left over by a crashed previous run.
func CleanupStale(runDir string) {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		cmdline, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(cmdline), "openvpn") || !strings.Contains(string(cmdline), runDir) {
			continue
		}
		if pid, err := strconv.Atoi(filepath.Base(filepath.Dir(p))); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	for slot := 0; slot < maxSlots; slot++ {
		cleanupTable(tableBase + slot)
	}
}

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
