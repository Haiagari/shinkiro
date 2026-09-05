package mongo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

type Decoy struct{}

func New() *Decoy {
	return &Decoy{}
}

func (d *Decoy) Name() string     { return "mongo" }
func (d *Decoy) DefaultPort() int { return 27017 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}

	msgLen := binary.LittleEndian.Uint32(header[0:4])
	opCode := binary.LittleEndian.Uint32(header[12:16])

	event := intel.Event{
		ID:          fmt.Sprintf("mongo-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "mongo",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   27017,
		Severity:    intel.SeverityHigh,
		ThreatScore: 70,
		Action:      fmt.Sprintf("OP_CODE_%d", opCode),
	}

	bodyLen := int(msgLen) - 16
	if bodyLen > 0 && bodyLen < 8192 {
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err == nil {
			hash := sha256.Sum256(body)
			event.PayloadHashes = []string{hex.EncodeToString(hash[:])}
		}
	}

	// Dispatch event immediately before network write
	select {
	case events <- event:
	default:
	}

	// Craft a realistic BSON response for isMaster / hello
	// Minimal valid OP_MSG reply
	respBody := []byte{
		0x00, 0x00, 0x00, 0x00, // flags
		0x00,                   // body section 0
		0x2f, 0x00, 0x00, 0x00, // BSON Document length (47 bytes)
		0x01, 'i', 's', 'W', 'r', 'i', 't', 'a', 'b', 'l', 'e', 'P', 'r', 'i', 'm', 'a', 'r', 'y', 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // double 1.0 (true)
		0x01, 'o', 'k', 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // double 1.0 (ok: 1)
		0x00, // document terminator
	}

	totalLen := uint32(16 + len(respBody))
	respHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(respHeader[0:4], totalLen)
	binary.LittleEndian.PutUint32(respHeader[4:8], 1) // responseTo
	binary.LittleEndian.PutUint32(respHeader[8:12], 1)
	binary.LittleEndian.PutUint32(respHeader[12:16], 2013) // OP_MSG = 2013

	_, _ = conn.Write(respHeader)
	_, _ = conn.Write(respBody)

	return nil
}
