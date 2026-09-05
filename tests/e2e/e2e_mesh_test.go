package e2e

import (
	"context"
	"io"
	"net"
	nethttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/core"
	"github.com/Haiagari/shinkiro/internal/decoys/aws"
	"github.com/Haiagari/shinkiro/internal/decoys/docker"
	decoyhttp "github.com/Haiagari/shinkiro/internal/decoys/http"
	"github.com/Haiagari/shinkiro/internal/decoys/k8s"
	"github.com/Haiagari/shinkiro/internal/decoys/postgres"
	"github.com/Haiagari/shinkiro/internal/decoys/redis"
	"github.com/Haiagari/shinkiro/internal/decoys/ssh"
	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestE2E_FullMeshSimulation(t *testing.T) {
	// Allocate test ports to prevent collisions with host services
	cfg := &config.Config{
		NodeName:       "shinkiro-e2e-test",
		IdleTimeout:    5 * time.Second,
		MaxConnections: 100,
		Services: map[string]config.ServiceConfig{
			"ssh":      {Enabled: true, Port: 28022},
			"redis":    {Enabled: true, Port: 28079},
			"docker":   {Enabled: true, Port: 28375},
			"http":     {Enabled: true, Port: 28080},
			"postgres": {Enabled: true, Port: 28432},
			"k8s":      {Enabled: true, Port: 28443},
			"aws-imds": {Enabled: true, Port: 28169},
		},
	}

	events := make(chan intel.Event, 50)
	mux := core.NewMultiplexer(cfg, events)

	mux.RegisterDecoy(ssh.New())
	mux.RegisterDecoy(redis.New())
	mux.RegisterDecoy(docker.New())
	mux.RegisterDecoy(decoyhttp.New())
	mux.RegisterDecoy(postgres.New())
	mux.RegisterDecoy(k8s.New())
	mux.RegisterDecoy(aws.New())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mux.Start(ctx); err != nil {
		t.Fatalf("failed to start e2e mesh multiplexer: %v", err)
	}
	defer mux.Stop()

	// Wait for sockets to listen
	time.Sleep(50 * time.Millisecond)

	// 1. Test Redis Probe
	t.Run("Redis_Ping", func(t *testing.T) {
		conn, err := net.Dial("tcp", "127.0.0.1:28079")
		if err != nil {
			t.Fatalf("dial redis failed: %v", err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("PING\r\n"))
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		if string(buf[:n]) != "+PONG\r\n" {
			t.Fatalf("expected +PONG, got %s", string(buf[:n]))
		}
	})

	// 2. Test HTTP .env Trap
	t.Run("HTTP_Env_Trap", func(t *testing.T) {
		resp, err := nethttp.Get("http://127.0.0.1:28080/.env")
		if err != nil {
			t.Fatalf("GET /.env failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "shinkiro_canary_secret") {
			t.Fatalf("expected canary secret in .env response: %s", string(body))
		}
	})

	// 3. Test Docker Daemon Ping
	t.Run("Docker_Version", func(t *testing.T) {
		resp, err := nethttp.Get("http://127.0.0.1:28375/version")
		if err != nil {
			t.Fatalf("GET /version failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "24.0.7") {
			t.Fatalf("expected docker version: %s", string(body))
		}
	})

	// 4. Test K8s Discovery
	t.Run("K8s_Version", func(t *testing.T) {
		resp, err := nethttp.Get("http://127.0.0.1:28443/version")
		if err != nil {
			t.Fatalf("GET /version on k8s failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "v1.29.2") {
			t.Fatalf("expected k8s version: %s", string(body))
		}
	})

	// 5. Test AWS IMDS SSRF Trap
	t.Run("AWS_IMDS_SSRF", func(t *testing.T) {
		resp, err := nethttp.Get("http://127.0.0.1:28169/latest/meta-data/iam/security-credentials/shinkiro-prod-cluster-role")
		if err != nil {
			t.Fatalf("GET IAM credentials failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "AKIA_SHINKIRO_CANARY") {
			t.Fatalf("expected canary IAM key: %s", string(body))
		}
	})

	// Ensure all events were captured in the pipeline
	eventCount := 0
	timeout := time.After(2 * time.Second)
drainLoop:
	for {
		select {
		case <-events:
			eventCount++
			if eventCount >= 5 {
				break drainLoop
			}
		case <-timeout:
			break drainLoop
		}
	}

	if eventCount < 5 {
		t.Fatalf("expected at least 5 telemetry events, captured: %d", eventCount)
	}
}
