package redis

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestRedisDecoy_InfoCommand(t *testing.T) {
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

	// Send INFO
	_, err := client.Write([]byte("INFO\r\n"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "redis_version:7.2.4") {
		t.Fatalf("expected redis version in response, got: %s", resp)
	}

	select {
	case ev := <-events:
		if ev.Action != "INFO" {
			t.Errorf("expected action INFO, got %s", ev.Action)
		}
		if ev.Severity != intel.SeverityHigh {
			t.Errorf("expected HIGH severity, got %s", ev.Severity)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for event")
	}
}
