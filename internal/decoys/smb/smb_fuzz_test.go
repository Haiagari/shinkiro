package smb

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func FuzzSMBDecoy(f *testing.F) {
	seeds := [][]byte{
		// NetBIOS header + SMBv2 negotiate sync
		{0x00, 0x00, 0x00, 0x20, 0xfe, 'S', 'M', 'B'},
		// EternalBlue probe fragment (MS17-010)
		{0x00, 0x00, 0x00, 0x44, 0xff, 'S', 'M', 'B', 0x72, 0x00, 0x00, 0x00},
		// Truncated NetBIOS header
		{0x00, 0x00},
		// Empty packet
		{},
		// Garbage / Boundary data
		{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03},
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
