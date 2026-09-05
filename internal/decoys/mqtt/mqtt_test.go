package mqtt

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestMQTTDecoy(t *testing.T) {
	d := New()
	if d.Name() != "mqtt" {
		t.Fatalf("expected 'mqtt', got %s", d.Name())
	}
	if d.DefaultPort() != 1883 {
		t.Fatalf("expected port 1883, got %d", d.DefaultPort())
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

	// 1. Send CONNECT packet
	// Header: 0x10, len: 27
	// Proto: 0x00, 0x04, 'M', 'Q', 'T', 'T', Level: 0x04, Flags: 0xC2 (User + Pass + CleanSession), Keepalive: 0x00, 0x3c
	// ClientID: 0x00, 0x03, 'b', 'o', 't'
	// User: 0x00, 0x04, 'r', 'o', 'o', 't'
	// Pass: 0x00, 0x04, 't', 'o', 'o', 'r'
	connectPacket := []byte{
		0x10, 27,
		0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xC2, 0x00, 0x3c,
		0x00, 0x03, 'b', 'o', 't',
		0x00, 0x04, 'r', 'o', 'o', 't',
		0x00, 0x04, 't', 'o', 'o', 'r',
	}

	_, err := clientConn.Write(connectPacket)
	if err != nil {
		t.Fatalf("failed to write connect packet: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Action != "MQTT_IOT_BOTNET_CONNECT" {
			t.Errorf("unexpected action: %s", ev.Action)
		}
		if ev.Username != "root" || ev.Password != "toor" {
			t.Errorf("unexpected user/pass: %s/%s", ev.Username, ev.Password)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for MQTT connect event")
	}

	// Read CONNACK response
	connack := make([]byte, 4)
	_, err = clientConn.Read(connack)
	if err != nil || connack[0] != 0x20 {
		t.Fatalf("invalid CONNACK: %v, %x", err, connack)
	}

	// 2. Send PUBLISH packet
	// Topic: 0x00, 0x07, "sensors" (9 bytes) + msg: "pwned" (5 bytes) = 14 bytes
	pubPacket := []byte{
		0x30, 14,
		0x00, 0x07, 's', 'e', 'n', 's', 'o', 'r', 's',
		'p', 'w', 'n', 'e', 'd',
	}
	_, _ = clientConn.Write(pubPacket)

	select {
	case ev := <-events:
		if ev.Action != "MQTT_IOT_EXPLOIT_PUBLISH" {
			t.Errorf("unexpected publish action: %s", ev.Action)
		}
		if ev.Command != "sensors" {
			t.Errorf("unexpected topic: %s", ev.Command)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for MQTT publish event")
	}

	// Send DISCONNECT
	_, _ = clientConn.Write([]byte{0xe0, 0x00})
}
