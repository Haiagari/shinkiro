package modbus

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestModbusDecoy_ReadHoldingRegisters(t *testing.T) {
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

	// MBAP Header (7 bytes) + PDU (Function 0x03, Start 0, Count 2)
	req := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID (Modbus)
		0x00, 0x06, // Length (6 bytes to follow)
		0x01,       // Unit ID
		0x03,       // Function Code: Read Holding Registers
		0x00, 0x00, // Start address: 0
		0x00, 0x02, // Count: 2
	}

	if _, err := client.Write(req); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if n < 9 {
		t.Fatalf("expected at least 9 bytes in response, got %d", n)
	}

	// Verify Function Code echo
	if buf[7] != 0x03 {
		t.Fatalf("expected function code 0x03 in response, got %x", buf[7])
	}

	select {
	case ev := <-events:
		if ev.DecoyName != "modbus" {
			t.Errorf("expected decoy name modbus, got %s", ev.DecoyName)
		}
		if ev.LocalPort != 502 {
			t.Errorf("expected port 502, got %d", ev.LocalPort)
		}
		if ev.Mitre == nil || ev.Mitre.TechniqueID != "T0855" {
			t.Errorf("expected MITRE ICS technique T0855, got %v", ev.Mitre)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for modbus event")
	}
}

func FuzzModbusDecoy(f *testing.F) {
	seeds := [][]byte{
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02},
		{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xFF, 0x00},
		{},
		{0xFF, 0xFF},
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		d := New()
		server, client := net.Pipe()
		events := make(chan intel.Event, 10)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = d.HandleConnection(ctx, server, events)
		}()

		go func() {
			for range events {
			}
		}()

		go func() {
			_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = client.Write(data)
			_ = client.Close()
		}()

		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			_ = server.Close()
			<-done
		}
	})
}
