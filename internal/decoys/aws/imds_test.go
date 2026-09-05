package aws

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestIMDSDecoy_SecurityCredentials(t *testing.T) {
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

	req := "GET /latest/meta-data/iam/security-credentials/shinkiro-prod-cluster-role HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "AKIA_SHINKIRO_CANARY_IAM_ROLE") {
		t.Fatalf("expected canary IAM role in response: %s", resp)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "aws-imds" {
			t.Errorf("expected aws-imds decoy, got %s", ev.DecoyName)
		}
		if ev.Severity != intel.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", ev.Severity)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for IMDS event")
	}
}
