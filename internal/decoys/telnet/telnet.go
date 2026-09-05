package telnet

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

func (d *Decoy) Name() string     { return "telnet" }
func (d *Decoy) DefaultPort() int { return 2323 } // Default non-root port
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	// 1. Send IAC negotiation bytes & BusyBox login prompt
	// IAC DO ECHO, IAC DO SUPPRESS_GO_AHEAD
	iac := []byte{0xff, 0xfd, 0x01, 0xff, 0xfd, 0x03}
	_, _ = conn.Write(iac)
	_, _ = conn.Write([]byte("\r\nEmbedded Linux Router (Busybox v1.31.1)\r\nlogin: "))

	reader := bufio.NewReader(conn)
	userLine, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	user := strings.TrimSpace(cleanIAC(userLine))
	_, _ = conn.Write([]byte("Password: "))

	passLine, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	pass := strings.TrimSpace(cleanIAC(passLine))

	event := intel.Event{
		ID:          fmt.Sprintf("telnet-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "telnet",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   2323,
		Severity:    intel.SeverityCritical,
		ThreatScore: 90,
		Action:      "TELNET_MIRAI_BOTNET_LOGIN",
		Username:    user,
		Password:    pass,
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", user, pass)))
	event.PayloadHashes = []string{hex.EncodeToString(hash[:])}

	select {
	case events <- event:
	default:
	}

	// Trap interactive botnet shell execution
	_, _ = conn.Write([]byte("\r\n\r\nBusyBox v1.31.1 multi-call binary.\r\n# "))

	for {
		cmdLine, cErr := reader.ReadString('\n')
		if cErr != nil {
			return nil
		}

		cmd := strings.TrimSpace(cleanIAC(cmdLine))
		if cmd != "" {
			cmdEvent := intel.Event{
				ID:          fmt.Sprintf("telnet-cmd-%d", time.Now().UnixNano()),
				Timestamp:   time.Now().UTC(),
				DecoyName:   "telnet",
				RemoteAddr:  remoteAddr,
				RemoteIP:    remoteIP,
				LocalPort:   2323,
				Severity:    intel.SeverityCritical,
				ThreatScore: 100,
				Action:      "TELNET_EXEC",
				Username:    user,
				Command:     cmd,
			}
			cHash := sha256.Sum256([]byte(cmd))
			cmdEvent.PayloadHashes = []string{hex.EncodeToString(cHash[:])}

			select {
			case events <- cmdEvent:
			default:
			}

			if cmd == "exit" || cmd == "quit" {
				return nil
			}

			// Emulate typical Mirai / botnet recon commands
			switch cmd {
			case "/bin/busybox MIRAI", "cat /bin/busybox":
				_, _ = conn.Write([]byte("MIRAI: applet not found\r\n# "))
			case "sh", "shell":
				_, _ = conn.Write([]byte("# "))
			default:
				_, _ = conn.Write([]byte(fmt.Sprintf("/bin/sh: %s: not found\r\n# ", cmd)))
			}
		} else {
			_, _ = conn.Write([]byte("# "))
		}
	}
}

func cleanIAC(s string) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		if b >= 32 && b <= 126 {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}
