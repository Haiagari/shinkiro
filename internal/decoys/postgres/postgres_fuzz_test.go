package postgres

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func FuzzPostgresDecoy(f *testing.F) {
	// Seed startup packet (SSL request, regular startup packet)
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)

	normStartup := []byte{
		0, 0, 0, 27, // length
		0, 3, 0, 0, // protocol 3.0
		'u', 's', 'e', 'r', 0, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0,
		'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0, 't', 'e', 's', 't', 0, 0,
	}

	f.Add(sslReq)
	f.Add(normStartup)
	f.Add([]byte("GARBAGE_PAYLOAD_TEST"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		d := New()
		server, client := net.Pipe()
		events := make(chan intel.Event, 20)
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
