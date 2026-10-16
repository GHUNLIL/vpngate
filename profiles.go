package main

import (
	"embed"
	"fmt"
	"os"
	"strings"
)

//go:embed deploy/profiles/*.env
var profiles embed.FS

// profileConfig only changes public tuning parameters; credentials and ACLs stay intact.
func profileConfig(current, name string) (string, error) {
	if name != "balanced" && name != "low-bandwidth" {
		return "", fmt.Errorf("未知预设 %q，可选 balanced 或 low-bandwidth", name)
	}
	data, err := profiles.ReadFile("deploy/profiles/" + name + ".env")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			found := false
			for _, existing := range strings.Split(current, "\n") {
				if strings.HasPrefix(existing, key+"=") {
					found = true
					break
				}
			}
			if found {
				current = setEnv(current, key, value)
			} else {
				current = strings.TrimRight(current, "\n") + "\n" + key + "=" + value + "\n"
			}
		}
	}
	return current, nil
}

func selectProfile(name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("请使用 root 运行")
	}
	data, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	updated, err := profileConfig(string(data), name)
	if err != nil {
		return err
	}
	if err := os.WriteFile(envPath+".before-profile", data, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(envPath, []byte(updated), 0o600); err != nil {
		return err
	}
	if err := shell("systemctl", "restart", "vpngate"); err != nil {
		_ = os.WriteFile(envPath, data, 0o600)
		_ = shell("systemctl", "restart", "vpngate")
		return fmt.Errorf("应用预设失败，已恢复配置: %w", err)
	}
	fmt.Println("已应用预设", name, "（账号、密码、端口及来源白名单保持不变）")
	return nil
}
