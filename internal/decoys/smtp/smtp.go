package smtp

import (
	"bufio"
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

func (d *Decoy) Name() string     { return "smtp" }
func (d *Decoy) DefaultPort() int { return 2525 } // Alternate port for non-root testing
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	// 1. Send Postfix / ESMTP banner
	_, _ = conn.Write([]byte("220 mail.shinkiro-sec.net ESMTP Postfix (Debian/GNU)\r\n"))

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil
		}

		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToUpper(parts[0])
		event := intel.Event{
			ID:          fmt.Sprintf("smtp-%d", time.Now().UnixNano()),
			Timestamp:   time.Now().UTC(),
			DecoyName:   "smtp",
			RemoteAddr:  remoteAddr,
			RemoteIP:    remoteIP,
			LocalPort:   2525,
			Severity:    intel.SeverityLow,
			ThreatScore: 30,
			Action:      cmd,
			Command:     line,
		}

		switch cmd {
		case "EHLO", "HELO":
			_, _ = conn.Write([]byte("250-mail.shinkiro-sec.net\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"))
		case "MAIL":
			event.Severity = intel.SeverityMedium
			event.ThreatScore = 50
			_, _ = conn.Write([]byte("250 2.1.0 Ok\r\n"))
		case "RCPT":
			event.Severity = intel.SeverityHigh
			event.ThreatScore = 75
			_, _ = conn.Write([]byte("250 2.1.5 Ok\r\n"))
		case "DATA":
			event.Severity = intel.SeverityCritical
			event.ThreatScore = 90
			_, _ = conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
			// Read mail body
			var body strings.Builder
			for {
				bLine, bErr := reader.ReadString('\n')
				if bErr != nil {
					break
				}
				if strings.TrimSpace(bLine) == "." {
					break
				}
				body.WriteString(bLine)
			}
			hash := sha256.Sum256([]byte(body.String()))
			event.PayloadHashes = []string{hex.EncodeToString(hash[:])}
			_, _ = conn.Write([]byte("250 2.0.0 Ok: queued as 4A8B9C1D2\r\n"))
		case "QUIT":
			_, _ = conn.Write([]byte("221 2.0.0 Bye\r\n"))
			return nil
		default:
			_, _ = conn.Write([]byte("502 5.5.2 Error: command not recognized\r\n"))
		}

		select {
		case events <- event:
		default:
		}
	}
}
