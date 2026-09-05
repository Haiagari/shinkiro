package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/intel"
)

type mockDecoy struct {
	name        string
	port        int
	calledCount int
}

func (m *mockDecoy) Name() string        { return m.name }
func (m *mockDecoy) DefaultPort() int    { return m.port }
func (m *mockDecoy) Protocol() string    { return "tcp" }
func (m *mockDecoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	m.calledCount++
	events <- intel.Event{
		DecoyName: m.name,
		Action:    "connected",
	}
	return nil
}

func TestMultiplexer_Lifecycle(t *testing.T) {
	cfg := &config.Config{
		IdleTimeout: 2 * time.Second,
		Services: map[string]config.ServiceConfig{
			"mock-service": {Enabled: true, Port: 29999},
		},
	}

	events := make(chan intel.Event, 10)
	mux := NewMultiplexer(cfg, events)

	decoy := &mockDecoy{name: "mock-service", port: 29999}
	mux.RegisterDecoy(decoy)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mux.Start(ctx); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}

	// Connect to test listener
	conn, err := net.Dial("tcp", "127.0.0.1:29999")
	if err != nil {
		t.Fatalf("failed to dial mock service: %v", err)
	}
	conn.Close()

	select {
	case ev := <-events:
		if ev.DecoyName != "mock-service" {
			t.Errorf("expected decoy mock-service, got %s", ev.DecoyName)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for event")
	}

	mux.Stop()
}
