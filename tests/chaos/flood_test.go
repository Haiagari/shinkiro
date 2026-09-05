package chaos

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/core"
	decoyhttp "github.com/Haiagari/shinkiro/internal/decoys/http"
	"github.com/Haiagari/shinkiro/internal/intel"
)

// TestChaos_ConcurrentConnectionSpike tests stability under massive simultaneous port connection bursts
func TestChaos_ConcurrentConnectionSpike(t *testing.T) {
	cfg := &config.Config{
		NodeName:       "shinkiro-chaos-node",
		IdleTimeout:    1 * time.Second,
		MaxConnections: 5000,
		Services: map[string]config.ServiceConfig{
			"http": {Enabled: true, Port: 29080},
		},
	}

	events := make(chan intel.Event, 2000)
	mux := core.NewMultiplexer(cfg, events)
	mux.RegisterDecoy(decoyhttp.New())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mux.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer mux.Stop()

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	concurrentClients := 100

	for i := 0; i < concurrentClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", "127.0.0.1:29080")
			if err != nil {
				return
			}
			defer conn.Close()

			req := fmt.Sprintf("GET /test-probe-%d HTTP/1.1\r\nHost: localhost\r\n\r\n", id)
			_, _ = conn.Write([]byte(req))

			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
		}(i)
	}

	wg.Wait()

	// Drain events safely without deadlocks
	received := 0
	timeout := time.After(1 * time.Second)
drain:
	for {
		select {
		case <-events:
			received++
		case <-timeout:
			break drain
		}
	}

	if received == 0 {
		t.Fatalf("expected events received during burst, got 0")
	}
}
