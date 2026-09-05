package aws

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

func (d *Decoy) Name() string     { return "aws-imds" }
func (d *Decoy) DefaultPort() int { return 8169 } // Proxied or bound to 169.254.169.254 / test port
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
	imdsToken := req.Header.Get("X-aws-ec2-metadata-token")

	event := intel.Event{
		ID:          fmt.Sprintf("imds-%d", time.Now().UnixNano()),
		Timestamp:   time.Now().UTC(),
		DecoyName:   "aws-imds",
		RemoteAddr:  remoteAddr,
		RemoteIP:    remoteIP,
		LocalPort:   8169,
		Severity:    intel.SeverityHigh,
		ThreatScore: 80,
		Action:      fmt.Sprintf("%s %s", req.Method, path),
		Metadata: map[string]string{
			"user_agent": req.UserAgent(),
		},
	}

	var respBody string
	var contentType = "text/plain"
	var headers = make(map[string]string)

	switch {
	case req.Method == "PUT" && path == "/latest/api/token":
		// IMDSv2 Token Request
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 90
		respBody = "AQAAAHYshinkiro_canary_imds_token_v2_f89b21a=="
		headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
	case strings.Contains(path, "security-credentials"):
		// IAM Role credential theft probe (Critical SSRF target)
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 100
		if path == "/latest/meta-data/iam/security-credentials/" || path == "/latest/meta-data/iam/security-credentials" {
			respBody = "shinkiro-prod-cluster-role\n"
		} else {
			// Serve Honeytoken AWS credentials to trace attacker movement across AWS
			respBody = `{
  "Code": "Success",
  "LastUpdated": "2026-09-04T18:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIA_SHINKIRO_CANARY_IAM_ROLE_99",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY_SHINKIRO_CANARY",
  "Token": "FwoGZXIvYXdzEJr//////////wEaEHQ_SHINKIRO_CANARY_SESSION_TOKEN==",
  "Expiration": "2026-09-05T06:00:00Z"
}`
			contentType = "application/json"
		}
	case strings.Contains(path, "instance-id"):
		respBody = "i-098a72b19cf89a2b1\n"
	case strings.Contains(path, "user-data"):
		event.Severity = intel.SeverityCritical
		event.ThreatScore = 95
		respBody = "#!/bin/bash\necho 'Provisioning shinkiro cloud host...'\n"
	default:
		respBody = "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\npublic-ipv4\n"
	}

	hash := sha256.Sum256([]byte(path + ":" + imdsToken))
	event.PayloadHashes = []string{hex.EncodeToString(hash[:])}

	// Send HTTP response
	var headerStr strings.Builder
	for k, v := range headers {
		headerStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nServer: EC2ws\r\n%sConnection: close\r\n\r\n%s",
		contentType, len(respBody), headerStr.String(), respBody)
	_, _ = conn.Write([]byte(resp))

	select {
	case events <- event:
	default:
	}

	return nil
}
