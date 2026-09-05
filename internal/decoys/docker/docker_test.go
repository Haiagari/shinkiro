package docker

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestDockerDecoy_Version(t *testing.T) {
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

	req := "GET /version HTTP/1.1\r\nHost: localhost:2375\r\n\r\n"
	_, err := client.Write([]byte(req))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "24.0.7") {
		t.Fatalf("expected docker version 24.0.7 in response, got: %s", resp)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "docker" {
			t.Errorf("expected docker decoy, got %s", ev.DecoyName)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for event")
	}
}
