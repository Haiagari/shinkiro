package elastic

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

func (d *Decoy) Name() string     { return "elastic" }
func (d *Decoy) DefaultPort() int { return 9200 }
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

	path := req.URL.Path
	event := intel.Event{
		ID:          fmt.Sprintf("es-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "elastic",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   9200,
		Severity:    intel.SeverityMedium,
		ThreatScore: 50,
		Action:      fmt.Sprintf("%s %s", req.Method, path),
	}

	var respBody string
	var statusCode = 200

	switch {
	case path == "/" || path == "":
		respBody = `{
  "name" : "shinkiro-data-node-01",
  "cluster_name" : "production-cluster",
  "cluster_uuid" : "a8b9c1d2e3f4",
  "version" : {
    "number" : "8.12.0",
    "build_flavor" : "default",
    "build_type" : "tar",
    "build_hash" : "161d65a240c29ea526e3be5f40f123c8682351dc",
    "lucene_version" : "9.9.1"
  },
  "tagline" : "You Know, for Search"
}`
	case strings.Contains(path, "_cat/indices"):
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 90
		respBody = "green open customer-pii-records-2026 a8b9 5 1 450123 0 1.2gb 600mb\ngreen open corporate-vault-secrets-audit c1d2 3 1 12450 0 45mb 22mb\n"
	case req.Method == "DELETE":
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 100
		respBody = `{"acknowledged":true}`
	default:
		respBody = `{"error":"no such index","status":404}`
		statusCode = 404
	}

	hash := sha256.Sum256([]byte(req.Method + ":" + path))
	event.PayloadHashes = []string{hex.EncodeToString(hash[:])}

	resp := fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, len(respBody), respBody)
	_, _ = conn.Write([]byte(resp))

	select {
	case events <- event:
	default:
	}

	return nil
}
