package mqtt

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func FuzzMQTTDecoy(f *testing.F) {
	seeds := [][]byte{
		// Valid CONNECT packet (clean)
		{0x10, 0x0C, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00},
		// CONNECT with user/pass
		{0x10, 27, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xC2, 0x00, 0x3c, 0x00, 0x03, 'b', 'o', 't', 0x00, 0x04, 'r', 'o', 'o', 't', 0x00, 0x04, 't', 'o', 'o', 'r'},
		// Truncated remaining length
		{0x10, 0xFF, 0xFF, 0xFF, 0x7F},
		// Short packet
		{0x10},
		// Empty packet
		{},
		// Garbage / Binary fuzz
		{0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01},
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
