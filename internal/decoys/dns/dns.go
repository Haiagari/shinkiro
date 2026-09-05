package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

type Decoy struct{}

func New() *Decoy {
	return &Decoy{}
}

func (d *Decoy) Name() string     { return "dns" }
func (d *Decoy) DefaultPort() int { return 5353 } // Non-privileged default
func (d *Decoy) Protocol() string { return "udp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}

	// Extract queried domain name starting at byte 12
	domain := parseDNSQuestion(buf[12:n])
	event := intel.Event{
		ID:          fmt.Sprintf("dns-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "dns",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   5353,
		Severity:    intel.SeverityMedium,
		ThreatScore: 40,
		Action:      fmt.Sprintf("DNS_QUERY %s", domain),
	}

	hash := sha256.Sum256([]byte(domain))
	event.PayloadHashes = []string{hex.EncodeToString(hash[:])}

	select {
	case events <- event:
	default:
	}

	return nil
}

func parseDNSQuestion(b []byte) string {
	var parts []string
	idx := 0
	for idx < len(b) {
		length := int(b[idx])
		if length == 0 || idx+1+length > len(b) {
			break
		}
		parts = append(parts, string(b[idx+1:idx+1+length]))
		idx += 1 + length
	}
	return strings.Join(parts, ".")
}
