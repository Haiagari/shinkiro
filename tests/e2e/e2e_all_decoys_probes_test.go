package e2e

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func probePostgres(t *testing.T) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:29432", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if err != nil || n != 1 || buf[0] != 'N' {
		t.Fatalf("ssl n=%d err=%v", n, err)
	}
	params := []byte{'u', 's', 'e', 'r', 0, 'e', '2', 'e', 0, 'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0, 0}
	msg := make([]byte, 8+len(params))
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.BigEndian.PutUint32(msg[4:8], 196608)
	copy(msg[8:], params)
	_, _ = c.Write(msg)
	auth := make([]byte, 9)
	if _, err := io.ReadFull(c, auth); err != nil || auth[0] != 'R' {
		t.Fatalf("auth err=%v", err)
	}
}

func probeSMTP(t *testing.T) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:29525", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "220 ") {
		t.Fatalf("banner %q", buf[:n])
	}
	_, _ = c.Write([]byte("HELO e2e.test\r\n"))
	n, _ = c.Read(buf)
	if !strings.Contains(string(buf[:n]), "250") {
		t.Fatalf("helo %q", buf[:n])
	}
}

func probeTelnet(t *testing.T) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:29323", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("admin\n"))
	time.Sleep(20 * time.Millisecond)
	_, _ = c.Write([]byte("admin\n"))
	buf := make([]byte, 512)
	if n, _ := c.Read(buf); n == 0 {
		t.Fatal("empty telnet")
	}
}

func probeMQTT(t *testing.T) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:29883", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	pkt := []byte{0x10, 27, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xC2, 0x00, 0x3c, 0x00, 0x03, 'b', 'o', 't', 0x00, 0x04, 'r', 'o', 'o', 't', 0x00, 0x04, 't', 'o', 'o', 'r'}
	_, _ = c.Write(pkt)
	ack := make([]byte, 4)
	n, err := c.Read(ack)
	if err != nil || n < 1 || ack[0] != 0x20 {
		t.Fatalf("connack n=%d err=%v", n, err)
	}
}

func probeMongo(t *testing.T) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:29017", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:4], 16)
	binary.LittleEndian.PutUint32(h[4:8], 1)
	binary.LittleEndian.PutUint32(h[12:16], 2013)
	_, _ = c.Write(h)
	resp := make([]byte, 16)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(resp[12:16]) != 2013 {
		t.Fatalf("opcode %d", binary.LittleEndian.Uint32(resp[12:16]))
	}
}
