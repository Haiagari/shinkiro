package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriter_WritePacket(t *testing.T) {
	var buf bytes.Buffer
	writer, err := NewWriter(&buf)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	payload := []byte("GET /sensitive-honeytoken HTTP/1.1\r\nHost: target\r\n\r\n")
	now := time.Now()
	if err := writer.WritePacket(now, payload); err != nil {
		t.Fatalf("failed to write packet: %v", err)
	}

	data := buf.Bytes()
	// GlobalHeader is 24 bytes, PacketHeader is 16 bytes
	if len(data) != 24+16+len(payload) {
		t.Fatalf("expected length %d, got %d", 24+16+len(payload), len(data))
	}

	var magic uint32
	_ = binary.Read(bytes.NewReader(data[:4]), binary.LittleEndian, &magic)
	if magic != 0xa1b2c3d4 {
		t.Fatalf("expected magic 0xa1b2c3d4, got 0x%x", magic)
	}
}

func TestCaptureFile_Lifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "dump.pcap")

	cf, err := OpenCapture(pcapPath)
	if err != nil {
		t.Fatalf("failed to open capture: %v", err)
	}

	err = cf.Write(time.Now(), []byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("failed to write packet: %v", err)
	}

	if err := cf.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}

	// Reopen existing capture file (should append without rewriting global header)
	cf2, err := OpenCapture(pcapPath)
	if err != nil {
		t.Fatalf("failed to reopen capture: %v", err)
	}
	_ = cf2.Write(time.Now(), []byte{0x05, 0x06})
	_ = cf2.Close()

	info, _ := os.Stat(pcapPath)
	// 24 (global) + (16+4) + (16+2) = 62 bytes
	if info.Size() != 62 {
		t.Fatalf("expected file size 62, got %d", info.Size())
	}
}
