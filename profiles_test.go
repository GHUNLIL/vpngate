package main

import (
	"strings"
	"testing"
)

func TestProfilesPreserveCredentialsAndACL(t *testing.T) {
	initial := "WEB_PASS=synthetic-admin-secret\nSS_PASSWORD=synthetic-proxy-secret\nSS_ALLOW=192.0.2.0/24\nWEB_PORT=54345\nSPEEDTEST_BYTES=4000000\n"
	low, err := profileConfig(initial, "low-bandwidth")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"WEB_PASS=synthetic-admin-secret", "SS_PASSWORD=synthetic-proxy-secret", "SS_ALLOW=192.0.2.0/24", "WEB_PORT=54345", "SPEEDTEST_BYTES=0", "ROTATE_NO_REPEAT=1", "CONNECT_TEST_URL=https://www.gstatic.com/generate_204", "HOLD_MINUTES=2"} {
		if !strings.Contains(low, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	balanced, err := profileConfig(low, "balanced")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SPEEDTEST_BYTES=4000000", "ROTATE_NO_REPEAT=0", "CONNECT_TEST_URL=", "HOLD_MINUTES=90"} {
		if !strings.Contains(balanced, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	again, _ := profileConfig(balanced, "balanced")
	if again != balanced {
		t.Fatal("profile application must be idempotent")
	}
	if _, err := profileConfig(initial, "../../private"); err == nil {
		t.Fatal("accepted invalid profile")
	}
}
