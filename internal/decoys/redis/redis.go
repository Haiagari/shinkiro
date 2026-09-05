package redis

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

func (d *Decoy) Name() string     { return "redis" }
func (d *Decoy) DefaultPort() int { return 6379 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle RESP inline or array commands
		parts := strings.Fields(line)
		cmd := strings.ToUpper(parts[0])

		event := intel.Event{
			ID:          fmt.Sprintf("redis-%d", time.Now().UnixNano()),
			Timestamp:   time.Now().UTC(),
			DecoyName:   "redis",
			RemoteAddr:  remoteAddr,
			RemoteIP:    remoteIP,
			LocalPort:   6379,
			Severity:    intel.SeverityMedium,
			ThreatScore: 40,
			Action:      cmd,
			Command:     line,
		}

		switch cmd {
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "INFO":
			event.Severity = intel.SeverityHigh
			event.ThreatScore = 65
			infoResp := "# Server\r\nredis_version:7.2.4\r\nos:Linux 6.6.137-amd64\r\ntcp_port:6379\r\nuptime_in_seconds:364210\r\n"
			resp := fmt.Sprintf("$%d\r\n%s\r\n", len(infoResp), infoResp)
			_, _ = conn.Write([]byte(resp))
		case "CONFIG":
			event.Severity = intel.SeverityCritical
			event.ThreatScore = 85
			_, _ = conn.Write([]byte("-ERR unknown command or insufficient permissions\r\n"))
		case "EVAL", "EVALSHA":
			event.Severity = intel.SeverityCritical
			event.ThreatScore = 95
			hash := sha256.Sum256([]byte(line))
			event.PayloadHashes = []string{hex.EncodeToString(hash[:])}
			_, _ = conn.Write([]byte("-ERR Error running script: sandbox evaluation blocked\r\n"))
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}

		select {
		case events <- event:
		default:
		}
	}
}
