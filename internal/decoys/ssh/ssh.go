package ssh

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
	gossh "golang.org/x/crypto/ssh"
)

type Decoy struct {
	signer gossh.Signer
}

func New() *Decoy {
	d := &Decoy{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err == nil {
		signer, err := gossh.NewSignerFromKey(key)
		if err == nil {
			d.signer = signer
		}
	}
	return d
}

func (d *Decoy) Name() string     { return "ssh" }
func (d *Decoy) DefaultPort() int { return 2222 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	var capturedUser, capturedPass string

	cfg := &gossh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
		PasswordCallback: func(c gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) {
			capturedUser = c.User()
			capturedPass = string(pass)
			return nil, nil
		},
		PublicKeyCallback: func(c gossh.ConnMetadata, pubKey gossh.PublicKey) (*gossh.Permissions, error) {
			capturedUser = c.User()
			capturedPass = "[PUBLIC_KEY: " + gossh.FingerprintSHA256(pubKey) + "]"
			return nil, nil
		},
	}

	if d.signer != nil {
		cfg.AddHostKey(d.signer)
	}

	sshConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		// Fallback probe
		ev := intel.Event{
			ID:          fmt.Sprintf("ssh-probe-%d", time.Now().UnixNano()),
			Timestamp:   time.Now().UTC(),
			DecoyName:   "ssh",
			RemoteAddr:  remoteAddr,
			RemoteIP:    remoteIP,
			LocalPort:   2222,
			Severity:    intel.SeverityMedium,
			ThreatScore: 40,
			Action:      "SSH_PROBE_CONNECT",
		}
		select {
		case events <- ev:
		default:
		}
		return nil
	}
	defer sshConn.Close()

	capturedUser = sshConn.User()

	loginEvent := intel.Event{
		ID:          fmt.Sprintf("ssh-login-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "ssh",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   2222,
		Severity:    intel.SeverityHigh,
		ThreatScore: 75,
		Action:      "SSH_LOGIN_SUCCESS_DECOY",
		Username:    capturedUser,
		Password:    capturedPass,
	}
	select {
	case events <- loginEvent:
	default:
	}

	go gossh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go d.handleSession(ctx, ch, requests, capturedUser, remoteIP, remoteAddr, events)
	}

	return nil
}

func (d *Decoy) handleSession(ctx context.Context, ch gossh.Channel, reqs <-chan *gossh.Request, user, ip, addr string, events chan<- intel.Event) {
	defer ch.Close()

	vfs := NewVirtualFS(user, "shinkiro-srv-prod01")
	reader := bufio.NewReader(ch)

	go func() {
		for req := range reqs {
			switch req.Type {
			case "pty-req", "shell":
				_ = req.Reply(true, nil)
			case "exec":
				_ = req.Reply(true, nil)
				if len(req.Payload) >= 4 {
					cmdLen := int(req.Payload[3])
					if len(req.Payload) >= 4+cmdLen {
						execCmd := string(req.Payload[4 : 4+cmdLen])
						d.recordCommand(execCmd, user, ip, addr, events)
						out := vfs.Execute(execCmd)
						_, _ = ch.Write([]byte(out))
					}
				}
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				ch.Close()
				return
			default:
				_ = req.Reply(false, nil)
			}
		}
	}()

	// Interactive Shell loop
	_, _ = ch.Write([]byte(fmt.Sprintf("Linux shinkiro-srv-prod01 6.6.137+deb12u1-amd64 #1 SMP Debian 6.6.137-1 x86_64\r\n\r\nThe programs included with the Debian GNU/Linux system are free software.\r\nLast login: %s from 192.168.1.100\r\n\r\n", time.Now().Add(-2*time.Hour).Format("Mon Jan 2 15:04:05 2006"))))
	_, _ = ch.Write([]byte(vfs.Prompt()))

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}

		cmd := strings.TrimSpace(line)
		if cmd != "" {
			d.recordCommand(cmd, user, ip, addr, events)
			if cmd == "exit" || cmd == "logout" {
				_, _ = ch.Write([]byte("logout\r\n"))
				return
			}

			output := vfs.Execute(cmd)
			output = strings.ReplaceAll(output, "\n", "\r\n")
			_, _ = ch.Write([]byte(output))
		}

		_, _ = ch.Write([]byte(vfs.Prompt()))
	}
}

func (d *Decoy) recordCommand(cmd, user, ip, addr string, events chan<- intel.Event) {
	hash := sha256.Sum256([]byte(cmd))
	score := 85
	severity := intel.SeverityHigh

	lower := strings.ToLower(cmd)
	if strings.Contains(lower, "curl") || strings.Contains(lower, "wget") || strings.Contains(lower, "base64") || strings.Contains(lower, "python") || strings.Contains(lower, "bash -i") {
		score = 100
		severity = intel.SeverityCritical
	}

	ev := intel.Event{
		ID:            fmt.Sprintf("ssh-cmd-%d", time.Now().UnixNano()),
		Timestamp:     time.Now().UTC(),
		DecoyName:     "ssh",
		RemoteAddr:    addr,
		RemoteIP:      ip,
		LocalPort:     2222,
		Severity:      severity,
		ThreatScore:   score,
		Action:        "SSH_EXEC_COMMAND",
		Username:      user,
		Command:       cmd,
		PayloadHashes: []string{hex.EncodeToString(hash[:])},
	}

	select {
	case events <- ev:
	default:
	}
}
