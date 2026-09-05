package smtp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestSMTPDecoy_HandshakeAndData(t *testing.T) {
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

	// Read initial banner
	buf := make([]byte, 256)
	n, _ := client.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "220 ") {
		t.Fatalf("expected 220 banner, got %s", string(buf[:n]))
	}

	// Send HELO
	_, _ = client.Write([]byte("HELO attacker.com\r\n"))
	n, _ = client.Read(buf)
	if !strings.Contains(string(buf[:n]), "250") {
		t.Fatalf("expected 250 response, got %s", string(buf[:n]))
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "smtp" {
			t.Errorf("expected smtp decoy, got %s", ev.DecoyName)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for smtp event")
	}
}
