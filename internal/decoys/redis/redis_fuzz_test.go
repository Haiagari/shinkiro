package redis

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func FuzzRedisDecoy(f *testing.F) {
	seeds := [][]byte{
		[]byte("PING\r\n"),
		[]byte("INFO\r\n"),
		[]byte("CONFIG GET *\r\n"),
		[]byte("EVAL \"return redis.call('get','foo')\" 0\r\n"),
		[]byte("*1\r\n$4\r\nPING\r\n"),
		[]byte("SET key value\r\n"),
		[]byte("GET key\r\n"),
		[]byte("\r\n\r\n"),
		[]byte(""),
		[]byte("\x00\xff\xfe\xfd"),
	}

	for _, seed := range seeds {
		f.Add(seed)
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
