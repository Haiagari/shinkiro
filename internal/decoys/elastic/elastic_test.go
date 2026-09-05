package elastic

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestElasticDecoy_RootAndIndices(t *testing.T) {
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

	req := "GET / HTTP/1.1\r\nHost: localhost:9200\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "You Know, for Search") {
		t.Fatalf("expected elastic tagline in response: %s", resp)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "elastic" {
			t.Errorf("expected elastic decoy, got %s", ev.DecoyName)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for elastic event")
	}
}
