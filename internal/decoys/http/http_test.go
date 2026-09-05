package http

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestHTTPDecoy_EnvTrap(t *testing.T) {
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

	req := "GET /.env HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "shinkiro_canary_secret") {
		t.Fatalf("expected canary secret in .env response: %s", resp)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "http" {
			t.Errorf("expected http decoy, got %s", ev.DecoyName)
		}
		if ev.Severity != intel.SeverityHigh {
			t.Errorf("expected HIGH severity for .env leak probe, got %s", ev.Severity)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for http event")
	}
}
