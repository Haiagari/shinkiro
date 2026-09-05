package docker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func FuzzDockerDecoy(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		[]byte("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		[]byte("GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		[]byte("POST /containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}"),
		[]byte("DELETE /containers/123 HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		[]byte("GARBAGE_HTTP_DATA\r\n\r\n"),
		[]byte(""),
	}

	for _, s := range seeds {
		f.Add(s)
	}

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
