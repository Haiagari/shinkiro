package pcap

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
	"time"
)

// Writer writes raw packet captures in standard libpcap 2.4 format
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// GlobalHeader libpcap file header
type GlobalHeader struct {
	MagicNumber  uint32 // 0xa1b2c3d4
	VersionMajor uint16 // 2
	VersionMinor uint16 // 4
	ThisZone     int32  // GMT to local correction
	SigFigs      uint32 // accuracy of timestamps
	SnapLen      uint32 // max length of captured packets
	Network      uint32 // data link type (1 = LINKTYPE_ETHERNET, 101 = LINKTYPE_RAW)
}

// PacketHeader per-packet libpcap header
type PacketHeader struct {
	TimestampSec  uint32
	TimestampUsec uint32
	CapLen        uint32
	Len           uint32
}

// NewWriter creates a pcap writer and writes the libpcap global file header
func NewWriter(w io.Writer) (*Writer, error) {
	pw := &Writer{w: w}
	gh := GlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      101, // LINKTYPE_RAW (raw IP packet)
	}

	if err := binary.Write(w, binary.LittleEndian, gh); err != nil {
		return nil, err
	}

	return pw, nil
}

// WritePacket logs a raw payload frame with timestamp
func (pw *Writer) WritePacket(t time.Time, data []byte) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	capLen := uint32(len(data))
	if capLen > 65535 {
		capLen = 65535
	}

	ph := PacketHeader{
		TimestampSec:  uint32(t.Unix()),
		TimestampUsec: uint32(t.Nanosecond() / 1000),
		CapLen:        capLen,
		Len:           uint32(len(data)),
	}

	if err := binary.Write(pw.w, binary.LittleEndian, ph); err != nil {
		return err
	}

	_, err := pw.w.Write(data[:capLen])
	return err
}

// CaptureFile wraps a managed pcap file logger
type CaptureFile struct {
	file   *os.File
	writer *Writer
}

// OpenCapture opens or creates a pcap capture file
func OpenCapture(path string) (*CaptureFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	var writer *Writer
	if stat.Size() == 0 {
		writer, err = NewWriter(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
	} else {
		writer = &Writer{w: f}
	}

	return &CaptureFile{file: f, writer: writer}, nil
}

// Write appends packet data
func (cf *CaptureFile) Write(t time.Time, data []byte) error {
	return cf.writer.WritePacket(t, data)
}

// Close closes the underlying pcap file
func (cf *CaptureFile) Close() error {
	return cf.file.Close()
}
