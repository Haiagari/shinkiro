package mongo

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestMongoDecoy_IsMasterProbe(t *testing.T) {
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

	// Build minimal MongoDB OP_MSG request
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], 16)
	binary.LittleEndian.PutUint32(header[4:8], 1)
	binary.LittleEndian.PutUint32(header[8:12], 0)
	binary.LittleEndian.PutUint32(header[12:16], 2013) // OP_MSG

	if _, err := client.Write(header); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	respHeader := make([]byte, 16)
	if _, err := client.Read(respHeader); err != nil {
		t.Fatalf("read header failed: %v", err)
	}

	opCode := binary.LittleEndian.Uint32(respHeader[12:16])
	if opCode != 2013 {
		t.Fatalf("expected OP_MSG (2013) reply, got %d", opCode)
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "mongo" {
			t.Errorf("expected mongo decoy, got %s", ev.DecoyName)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for mongo event")
	}
}
