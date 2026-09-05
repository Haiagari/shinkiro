package k8s

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

func (d *Decoy) Name() string     { return "k8s" }
func (d *Decoy) DefaultPort() int { return 6443 }
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

	authHeader := req.Header.Get("Authorization")
	path := req.URL.Path

	event := intel.Event{
		ID:          fmt.Sprintf("k8s-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "k8s",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   6443,
		Severity:    intel.SeverityHigh,
		ThreatScore: 75,
		Action:      fmt.Sprintf("%s %s", req.Method, path),
		Metadata: map[string]string{
			"user_agent": req.UserAgent(),
		},
	}

	if authHeader != "" {
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 95
		hash := sha256.Sum256([]byte(authHeader))
		event.PayloadHashes = []string{hex.EncodeToString(hash[:])}
		event.Metadata["auth_type"] = "bearer_token"
	}

	var respBody string
	var statusCode int = 200

	switch {
	case path == "/version":
		respBody = `{"major":"1","minor":"29","gitVersion":"v1.29.2","gitCommit":"4b1e7b3","platform":"linux/amd64"}`
	case path == "/api" || path == "/apis":
		respBody = `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"10.96.0.1:443"}]}`
	case strings.Contains(path, "secrets") || strings.Contains(path, "pods"):
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 100
		statusCode = 403
		respBody = `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get resource in API group \"\"","reason":"Forbidden","code":403}`
	default:
		statusCode = 404
		respBody = `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server could not find the requested resource","reason":"NotFound","code":404}`
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
