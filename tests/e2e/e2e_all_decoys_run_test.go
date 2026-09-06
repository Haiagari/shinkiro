package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/core"
	"github.com/Haiagari/shinkiro/internal/decoys"
	"github.com/Haiagari/shinkiro/internal/decoys/aws"
	"github.com/Haiagari/shinkiro/internal/decoys/dns"
	"github.com/Haiagari/shinkiro/internal/decoys/docker"
	"github.com/Haiagari/shinkiro/internal/decoys/elastic"
	decoyhttp "github.com/Haiagari/shinkiro/internal/decoys/http"
	"github.com/Haiagari/shinkiro/internal/decoys/k8s"
	"github.com/Haiagari/shinkiro/internal/decoys/modbus"
	"github.com/Haiagari/shinkiro/internal/decoys/mongo"
	"github.com/Haiagari/shinkiro/internal/decoys/mqtt"
	"github.com/Haiagari/shinkiro/internal/decoys/postgres"
	"github.com/Haiagari/shinkiro/internal/decoys/redis"
	"github.com/Haiagari/shinkiro/internal/decoys/smb"
	"github.com/Haiagari/shinkiro/internal/decoys/smtp"
	"github.com/Haiagari/shinkiro/internal/decoys/ssh"
	"github.com/Haiagari/shinkiro/internal/decoys/telnet"
	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestE2E_AllFifteenDecoys(t *testing.T) {
	if len(expectedDecoys) != 15 {
		t.Fatalf("expected 15 decoys, got %d", len(expectedDecoys))
	}
	cfg := allDecoyConfig()
	events := make(chan intel.Event, 128)
	mux := core.NewMultiplexer(cfg, events)
	for _, d := range []decoys.Decoy{
		ssh.New(), redis.New(), docker.New(), decoyhttp.New(), postgres.New(), k8s.New(), aws.New(),
		mongo.New(), elastic.New(), smtp.New(), dns.New(), smb.New(), telnet.New(), mqtt.New(), modbus.New(),
	} {
		mux.RegisterDecoy(d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mux.Start(ctx); err != nil {
		t.Fatalf("start mux: %v", err)
	}
	defer mux.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for _, name := range expectedDecoys {
		port := cfg.Services[name].Port
		for {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("listener %s :%d not ready: %v", name, port, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Probe each decoy with a minimal protocol-appropriate payload (high ports; no privileges).
	type step struct {
		name string
		fn   func(t *testing.T)
	}
	steps := []step{
		{"redis", func(t *testing.T) { mustTCP(t, 29079, []byte("PING\r\n"), "+PONG") }},
		{"http", func(t *testing.T) { mustHTTP(t, "http://127.0.0.1:29080/.env", "shinkiro_canary_secret") }},
		{"docker", func(t *testing.T) { mustHTTP(t, "http://127.0.0.1:29375/version", "24.0.7") }},
		{"k8s", func(t *testing.T) { mustHTTP(t, "http://127.0.0.1:29443/version", "v1.") }},
		{"aws-imds", func(t *testing.T) {
			mustHTTP(t, "http://127.0.0.1:29169/latest/meta-data/iam/security-credentials/role", "AKIA_SHINKIRO_CANARY")
		}},
		{"elastic", func(t *testing.T) { mustHTTP(t, "http://127.0.0.1:29200/", "You Know, for Search") }},
		{"postgres", func(t *testing.T) { probePostgres(t) }},
		{"smtp", func(t *testing.T) { probeSMTP(t) }},
		{"telnet", func(t *testing.T) { probeTelnet(t) }},
		{"smb", func(t *testing.T) { mustTCP(t, 29445, []byte{0x00, 0x00, 0x00, 0x20, 0xfe, 'S', 'M', 'B'}, "") }},
		{"mqtt", func(t *testing.T) { probeMQTT(t) }},
		{"modbus", func(t *testing.T) {
			mustTCP(t, 29502, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02}, "")
		}},
		{"mongo", func(t *testing.T) { probeMongo(t) }},
		{"dns", func(t *testing.T) {
			pkt := make([]byte, 27)
			pkt[0], pkt[1] = 0xAA, 0xBB
			copy(pkt[12:], []byte{0x08, 'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 0x04, 'c', 'o', 'r', 'p', 0x00})
			mustTCP(t, 29053, pkt, "")
		}},
		{"ssh", func(t *testing.T) { mustTCP(t, 29022, []byte("NOT-SSH\r\n"), "") }},
	}
	for _, s := range steps {
		t.Run(s.name, s.fn)
	}

	seen := map[string]bool{}
	timeout := time.After(5 * time.Second)
drain:
	for {
		select {
		case ev := <-events:
			seen[ev.DecoyName] = true
			if len(seen) >= 15 {
				break drain
			}
		case <-timeout:
			break drain
		}
	}
	var missing []string
	for _, name := range expectedDecoys {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("missing telemetry: %v (saw %d/15)", missing, len(seen))
	}
}

func mustHTTP(t *testing.T, url, want string) {
	t.Helper()
	resp, err := nethttp.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), want) {
		t.Fatalf("want %q in %s", want, b)
	}
}

func mustTCP(t *testing.T, port int, payload []byte, want string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if len(payload) > 0 {
		_, _ = c.Write(payload)
	}
	if want == "" {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		return
	}
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), want) {
		t.Fatalf("want %q got %q", want, buf[:n])
	}
}
