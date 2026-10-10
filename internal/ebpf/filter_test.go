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

func TestFilterManager_Concurrency(t *testing.T) {
	fm := NewFilterManager(DriverNFTables, "eth0")
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(workerID int) {
			for j := 0; j < 50; j++ {
				ip := "192.168.1.1"
				_ = fm.BlockIP(ip)
				_ = fm.IsBlocked(ip)
				_ = fm.RenderScript()
				_ = fm.UnblockIP(ip)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
