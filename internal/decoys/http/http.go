package http

import (
	"bufio"
	"context"
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

func (d *Decoy) Name() string     { return "http" }
func (d *Decoy) DefaultPort() int { return 8080 }
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
		ID:          fmt.Sprintf("http-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "http",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   8080,
		Severity:    intel.SeverityLow,
		ThreatScore: 20,
		Action:      fmt.Sprintf("%s %s", req.Method, path),
	}

	var respBody string
	var contentType = "text/plain"

	switch {
	case strings.Contains(path, ".env"):
		event.Severity = intel.SeverityHigh
		event.ThreatScore = 80
		respBody = "DB_HOST=127.0.0.1\nDB_USER=app_prod\nDB_PASS=shinkiro_canary_secret_99a8b1\nAWS_SECRET_ACCESS_KEY=AKIA_SHINKIRO_CANARY\n"
	case strings.Contains(path, ".git"):
		event.Severity = intel.SeverityHigh
		event.ThreatScore = 80
		respBody = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:internal/corporate-app.git\n"
	default:
		respBody = "<html><body><h1>404 Not Found</h1></body></html>"
		contentType = "text/html"
	}

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nServer: nginx/1.22.1\r\nConnection: close\r\n\r\n%s",
		contentType, len(respBody), respBody)
	_, _ = conn.Write([]byte(resp))

	select {
	case events <- event:
	default:
	}

	return nil
}
