package ebpf

import (
	"strings"
	"testing"
)

func TestFilterManager_NFTables(t *testing.T) {
	fm := NewFilterManager(DriverNFTables, "eth0")
	if err := fm.BlockIP("192.0.2.1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := fm.BlockIP("198.51.100.24"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	script := fm.RenderScript()
	if !strings.Contains(script, "192.0.2.1") || !strings.Contains(script, "198.51.100.24") {
		t.Fatalf("expected blocked IPs in script: %s", script)
	}
	if !strings.Contains(script, "table inet shinkiro_guard") {
		t.Fatalf("expected nftables table header: %s", script)
	}
}

func TestFilterManager_InvalidIP(t *testing.T) {
	fm := NewFilterManager(DriverIPTables, "eth0")
	if err := fm.BlockIP("invalid-ip-string"); err == nil {
		t.Fatalf("expected error on invalid IP, got nil")
	}
}
