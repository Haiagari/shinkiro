package e2e

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/core"
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

// expectedDecoys lists the 15 real decoy Name() values from cmd/shinkiro/up.go.
var expectedDecoys = []string{
	"ssh", "redis", "docker", "http", "postgres", "k8s", "aws-imds",
	"mongo", "elastic", "smtp", "dns", "smb", "telnet", "mqtt", "modbus",
}

// highPorts avoid privileged binds (no CAP_NET_BIND_SERVICE / root).
func allDecoyConfig() *config.Config {
	return &config.Config{
		NodeName:       "shinkiro-e2e-all-decoys",
		IdleTimeout:    5 * time.Second,
		MaxConnections: 200,
		Services: map[string]config.ServiceConfig{
			"ssh":      {Enabled: true, Port: 29022},
			"redis":    {Enabled: true, Port: 29079},
			"docker":   {Enabled: true, Port: 29375},
			"http":     {Enabled: true, Port: 29080},
			"postgres": {Enabled: true, Port: 29432},
			"k8s":      {Enabled: true, Port: 29443},
			"aws-imds": {Enabled: true, Port: 29169},
			"mongo":    {Enabled: true, Port: 29017},
			"elastic":  {Enabled: true, Port: 29200},
			"smtp":     {Enabled: true, Port: 29525},
			"dns":      {Enabled: true, Port: 29053},
			"smb":      {Enabled: true, Port: 29445},
			"telnet":   {Enabled: true, Port: 29323},
			"mqtt":     {Enabled: true, Port: 29883},
			"modbus":   {Enabled: true, Port: 29502},
		},
	}
}
