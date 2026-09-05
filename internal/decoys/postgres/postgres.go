package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

type Decoy struct{}

func New() *Decoy {
	return &Decoy{}
}

func (d *Decoy) Name() string     { return "postgres" }
func (d *Decoy) DefaultPort() int { return 5432 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil
	}

	length := binary.BigEndian.Uint32(header[0:4])
	protocol := binary.BigEndian.Uint32(header[4:8])

	// Check for SSLRequest: 80877103
	if protocol == 80877103 {
		// Respond 'N' (SSL not supported) so client sends plain auth
		_, _ = conn.Write([]byte("N"))
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil
		}
		length = binary.BigEndian.Uint32(header[0:4])
	}

	bodyLen := int(length) - 8
	var user, database string
	if bodyLen > 0 && bodyLen < 4096 {
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err == nil {
			params := parseStartupParams(body)
			user = params["user"]
			database = params["database"]
		}
	}

	event := intel.Event{
		ID:          fmt.Sprintf("pg-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "postgres",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   5432,
		Severity:    intel.SeverityHigh,
		ThreatScore: 70,
		Action:      "PG_AUTH_PROBE",
		Username:    user,
		Metadata: map[string]string{
			"database": database,
		},
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", user, database)))
	event.PayloadHashes = []string{hex.EncodeToString(hash[:])}

	// Send AuthenticationCleartextPassword request (AuthenticationOk = 0, Cleartext = 3)
	authReq := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}
	_, _ = conn.Write(authReq)

	// Read PasswordMessage ('p')
	pHeader := make([]byte, 5)
	if _, err := io.ReadFull(conn, pHeader); err == nil && pHeader[0] == 'p' {
		pLen := int(binary.BigEndian.Uint32(pHeader[1:5])) - 4
		if pLen > 0 && pLen < 1024 {
			pBody := make([]byte, pLen)
			if _, err := io.ReadFull(conn, pBody); err == nil {
				pass := strings.TrimRight(string(pBody), "\x00")
				event.Password = pass
				event.Severity = intel.SeverityCritical
				event.ThreatScore = 85
			}
		}
	}

	// Send ErrorResponse simulating password failure
	errStr := "SFATAL\x00C28P01\x00Mpassword authentication failed for user \"" + user + "\"\x00\x00"
	errLen := uint32(len(errStr) + 4)
	errMsg := make([]byte, 5+len(errStr))
	errMsg[0] = 'E'
	binary.BigEndian.PutUint32(errMsg[1:5], errLen)
	copy(errMsg[5:], errStr)
	_, _ = conn.Write(errMsg)

	select {
	case events <- event:
	default:
	}

	return nil
}

func parseStartupParams(body []byte) map[string]string {
	params := make(map[string]string)
	parts := strings.Split(string(body), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] != "" {
			params[parts[i]] = parts[i+1]
		}
	}
	return params
}
