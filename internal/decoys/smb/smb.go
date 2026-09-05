package smb

import (
	"context"
	"crypto/sha256"
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

func (d *Decoy) Name() string     { return "smb" }
func (d *Decoy) DefaultPort() int { return 445 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}

	event := intel.Event{
		ID:          fmt.Sprintf("smb-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "smb",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   445,
		Severity:    intel.SeverityCritical,
		ThreatScore: 90,
		Action:      "SMB_NEGOTIATE_PROBE",
	}

	// Dispatch event immediately to prevent channel delays
	select {
	case events <- event:
	default:
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		hash := sha256.Sum256(buf[:n])
		event.PayloadHashes = []string{hex.EncodeToString(hash[:])}
	}

	// Send realistic SMBv2 Negotiate Protocol Response (Dialect 0x0202)
	smbResp := []byte{
		0x00, 0x00, 0x00, 0x40, // NetBIOS session header (64 bytes)
		0xfe, 'S', 'M', 'B', // SMB2 magic
		0x40, 0x00, // Header length
		0x00, 0x00, // Credit charge
		0x00, 0x00, 0x00, 0x00, // Status: STATUS_SUCCESS
		0x00, 0x00, // Command: NEGOTIATE
		0x01, 0x00, // Credits granted
		0x01, 0x00, 0x00, 0x00, // Flags: SERVER_TO_REDIR
		0x00, 0x00, 0x00, 0x00, // Next command
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x41, 0x00, // Structure size
		0x01, 0x00, // Security mode: signing enabled
		0x02, 0x02, // Dialect revision: SMB 2.0.2
	}

	_, _ = conn.Write(smbResp)

	return nil
}
