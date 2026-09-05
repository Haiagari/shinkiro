package postgres

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestPostgresDecoy_AuthProbe(t *testing.T) {
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

	// Build Postgres StartupMessage: Length (4 bytes), Protocol 3.0 (4 bytes), params...
	payload := "user\x00admin\x00database\x00financial_db\x00\x00"
	msgLen := uint32(8 + len(payload))
	req := make([]byte, msgLen)
	binary.BigEndian.PutUint32(req[0:4], msgLen)
	binary.BigEndian.PutUint32(req[4:8], 196608) // 3.0
	copy(req[8:], []byte(payload))

	if _, err := client.Write(req); err != nil {
		t.Fatalf("startup write failed: %v", err)
	}

	// Read AuthenticationCleartextPassword response from decoy
	resp := make([]byte, 9)
	if _, err := client.Read(resp); err != nil {
		t.Fatalf("auth read failed: %v", err)
	}

	if resp[0] != 'R' {
		t.Fatalf("expected Auth request 'R', got %c", resp[0])
	}

	// Send PasswordMessage ('p')
	pass := "supersecret123\x00"
	pMsg := make([]byte, 5+len(pass))
	pMsg[0] = 'p'
	binary.BigEndian.PutUint32(pMsg[1:5], uint32(4+len(pass)))
	copy(pMsg[5:], []byte(pass))

	if _, err := client.Write(pMsg); err != nil {
		t.Fatalf("password write failed: %v", err)
	}

	// Read ErrorResponse ('E')
	errBuf := make([]byte, 256)
	n, err := client.Read(errBuf)
	if err != nil {
		t.Fatalf("error response read failed: %v", err)
	}

	if errBuf[0] != 'E' || !strings.Contains(string(errBuf[:n]), "password authentication failed") {
		t.Fatalf("expected failed auth error response, got: %s", string(errBuf[:n]))
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "postgres" {
			t.Errorf("expected postgres decoy, got %s", ev.DecoyName)
		}
		if ev.Username != "admin" {
			t.Errorf("expected user admin, got %s", ev.Username)
		}
		if ev.Password != "supersecret123" {
			t.Errorf("expected password captured, got %s", ev.Password)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for postgres event")
	}
}
