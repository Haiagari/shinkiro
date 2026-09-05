package smb

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestSMBDecoy_Negotiate(t *testing.T) {
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

	// Send SMB2 Negotiate header
	client.Write([]byte{0x00, 0x00, 0x00, 0x20, 0xfe, 'S', 'M', 'B'})

	buf := make([]byte, 68)
	n, err := client.Read(buf)
	if err != nil || n < 8 {
		t.Fatalf("failed to read SMB negotiate response: %v", err)
	}

	if buf[4] != 0xfe || buf[5] != 'S' || buf[6] != 'M' || buf[7] != 'B' {
		t.Fatalf("expected SMB2 magic response, got %x", buf[4:8])
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "smb" {
			t.Errorf("expected smb decoy, got %s", ev.DecoyName)
		}
		if ev.Severity != intel.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", ev.Severity)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for smb event")
	}
}
