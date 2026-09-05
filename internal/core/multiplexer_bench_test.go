package core

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/intel"
)

type fastBenchDecoy struct{}

func (f *fastBenchDecoy) Name() string     { return "bench" }
func (f *fastBenchDecoy) DefaultPort() int { return 9999 }
func (f *fastBenchDecoy) Protocol() string { return "tcp" }
func (f *fastBenchDecoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		_, _ = conn.Write([]byte("OK\r\n"))
	}
	return nil
}

func BenchmarkMultiplexer_ConcurrentConnections(b *testing.B) {
	cfg := &config.Config{
		NodeName:       "bench-node",
		IdleTimeout:    5 * time.Second,
		MaxConnections: 20000,
		Services: map[string]config.ServiceConfig{
			"bench": {Enabled: true, Port: 0}, // ephemeral port
		},
	}

	events := make(chan intel.Event, 50000)
	mux := NewMultiplexer(cfg, events)
	decoy := &fastBenchDecoy{}
	mux.RegisterDecoy(decoy)

	// Consume events to prevent channel block
	go func() {
		for range events {
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mux.Start(ctx); err != nil {
		b.Fatalf("failed to start multiplexer: %v", err)
	}
	defer mux.Stop()

	// Locate actual bound ephemeral port
	mux.mu.Lock()
	listener := mux.listeners[0]
	mux.mu.Unlock()
	addr := listener.Addr().String()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 16)
		for pb.Next() {
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err != nil {
				continue
			}
			_, _ = conn.Write([]byte("PING\r\n"))
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	})
}

func BenchmarkTelemetry_EventIngestionRate(b *testing.B) {
	events := make(chan intel.Event, 100000)
	var wg sync.WaitGroup

	// Consumer simulating the core pipeline
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-events:
			case <-done:
				return
			}
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()

	ev := intel.Event{
		ID:          "bench-ev-1",
		Timestamp:   time.Now(),
		DecoyName:   "ssh",
		RemoteIP:    "192.168.1.50",
		Severity:    intel.SeverityHigh,
		ThreatScore: 85,
		Action:      "SSH_AUTH_ATTEMPT",
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			select {
			case events <- ev:
			default:
			}
		}
	})

	close(done)
	wg.Wait()
}
