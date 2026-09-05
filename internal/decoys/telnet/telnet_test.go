package telnet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestTelnetDecoy_HandleConnection(t *testing.T) {
	d := New()
	if d.Name() != "telnet" {
		t.Fatalf("expected decoy name 'telnet', got %s", d.Name())
	}
	if d.DefaultPort() != 2323 {
		t.Fatalf("expected port 2323, got %d", d.DefaultPort())
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	events := make(chan intel.Event, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = d.HandleConnection(ctx, serverConn, events)
	}()

	// 1. Read initial banner (IAC + login prompt)
	buf := make([]byte, 1024)
	_, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read iac: %v", err)
	}

	// Read login prompt
	_, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read login prompt: %v", err)
	}

	// Send username
	_, _ = clientConn.Write([]byte("admin\n"))

	// Read password prompt
	_, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read password prompt: %v", err)
	}

	// Send password
	_, _ = clientConn.Write([]byte("123456\n"))

	// Verify login event
	select {
	case ev := <-events:
		if ev.Username != "admin" || ev.Password != "123456" {
			t.Errorf("unexpected credentials: %s/%s", ev.Username, ev.Password)
		}
		if ev.Action != "TELNET_MIRAI_BOTNET_LOGIN" {
			t.Errorf("unexpected action: %s", ev.Action)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for telnet login event")
	}

	// Read shell prompt
	_, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read shell prompt: %v", err)
	}

	// Send command
	_, _ = clientConn.Write([]byte("/bin/busybox MIRAI\n"))

	select {
	case ev := <-events:
		if ev.Command != "/bin/busybox MIRAI" {
			t.Errorf("unexpected command captured: %s", ev.Command)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for telnet command event")
	}

	// Drain command response from server so pipe doesn't block
	_, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read cmd response: %v", err)
	}

	// Send exit
	_, _ = clientConn.Write([]byte("exit\n"))
}
