package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestDNSDecoy_ParseQuestion(t *testing.T) {
	d := New()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	events := make(chan intel.Event, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = d.HandleConnection(ctx, server, events)
	}()

	// Build raw DNS packet for "internal.corp"
	// 12 bytes header + 8 bytes "\x08internal\x04corp\x00"
	packet := make([]byte, 12+15)
	packet[0] = 0xAA
	packet[1] = 0xBB // Transaction ID
	dnsQ := []byte{0x08, 'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 0x04, 'c', 'o', 'r', 'p', 0x00}
	copy(packet[12:], dnsQ)

	if _, err := client.Write(packet); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "dns" {
			t.Errorf("expected dns decoy, got %s", ev.DecoyName)
		}
		if !strings.Contains(ev.Action, "internal.corp") {
			t.Errorf("expected internal.corp in action, got %s", ev.Action)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for dns event")
	}
}
