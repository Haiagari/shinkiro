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
	case strings.Contains(path, "wp-login.php") || strings.Contains(path, "wp-admin"):
		event.Severity = intel.SeverityHigh
		event.ThreatScore = 75
		contentType = "text/html"
		respBody = `<!DOCTYPE html><html><head><title>WordPress &rsaquo; Log In</title></head><body class="login"><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" class="input" size="20" /></p><p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" class="input" size="20" /></p><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" /></p></form></body></html>`
	case strings.Contains(path, "grafana") || strings.Contains(path, "/api/v1/query"):
		event.Severity = intel.SeverityHigh
		event.ThreatScore = 75
		contentType = "application/json"
		respBody = `{"version":"10.2.3","database":"ok","commit":"0d86927","buildstamp":1704987654}`
	case strings.Contains(path, "jenkins") || strings.Contains(path, "j_spring_security_check"):
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 85
		contentType = "text/html"
		respBody = `<html><head><title>Jenkins [Jenkins]</title></head><body><h1>Sign in [Jenkins]</h1><form action="j_spring_security_check" method="POST"><input type="text" name="j_username" placeholder="Username"/><input type="password" name="j_password" placeholder="Password"/><input type="submit" value="Sign in"/></form></body></html>`
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
