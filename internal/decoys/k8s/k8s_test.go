package k8s

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestK8sDecoy_Version(t *testing.T) {
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

	req := "GET /version HTTP/1.1\r\nHost: 10.96.0.1:6443\r\nUser-Agent: kubectl/v1.29.0\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "v1.29.2") {
		t.Fatalf("expected k8s version in response, got: %s", resp)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "k8s" {
			t.Errorf("expected k8s decoy, got %s", ev.DecoyName)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for k8s event")
	}
}
