package docker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

type Decoy struct{}

func New() *Decoy {
	return &Decoy{}
}

func (d *Decoy) Name() string     { return "docker" }
func (d *Decoy) DefaultPort() int { return 2375 }
func (d *Decoy) Protocol() string { return "tcp" }

func (d *Decoy) HandleConnection(ctx context.Context, conn net.Conn, events chan<- intel.Event) error {
	remoteAddr := conn.RemoteAddr().String()
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil
	}
	defer req.Body.Close()

	event := intel.Event{
		ID:          fmt.Sprintf("docker-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "docker",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   2375,
		Severity:    intel.SeverityMedium,
		ThreatScore: 50,
		Action:      fmt.Sprintf("%s %s", req.Method, req.URL.Path),
	}

	var respBody string
	var statusCode int = 200

	switch {
	case req.URL.Path == "/_ping":
		respBody = "OK"
	case req.URL.Path == "/version" || strings.HasSuffix(req.URL.Path, "/version"):
		respBody = `{"Platform":{"Name":""},"Components":[{"Name":"Engine","Version":"24.0.7"}],"Version":"24.0.7","ApiVersion":"1.43","MinAPIVersion":"1.12","GitCommit":"afdd53b","GoVersion":"go1.20.10","Os":"linux","Arch":"amd64"}`
	case strings.Contains(req.URL.Path, "/containers/create"):
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 95
		// Read payload to extract image/command
		buf := make([]byte, 4096)
		n, _ := req.Body.Read(buf)
		payload := string(buf[:n])
		hash := sha256.Sum256(buf[:n])
		event.PayloadHashes = []string{hex.EncodeToString(hash[:])}
		event.Command = payload
		respBody = `{"Id":"e90e34656806","Warnings":[]}`
		statusCode = 201
	default:
		respBody = `[]`
	}

	resp := fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, len(respBody), respBody)
	_, _ = conn.Write([]byte(resp))

	select {
	case events <- event:
	default:
	}

	return nil
}
