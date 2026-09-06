package e2e

import (
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
)

// expectedDecoys: 15 real Name() values from cmd/shinkiro/up.go (do not invent).
var expectedDecoys = []string{
	"ssh", "redis", "docker", "http", "postgres", "k8s", "aws-imds",
	"mongo", "elastic", "smtp", "dns", "smb", "telnet", "mqtt", "modbus",
}

func allDecoyConfig() *config.Config {
	return &config.Config{
		NodeName: "shinkiro-e2e-all-decoys", IdleTimeout: 5 * time.Second, MaxConnections: 200,
		Services: map[string]config.ServiceConfig{
			"ssh": {Enabled: true, Port: 29022}, "redis": {Enabled: true, Port: 29079},
			"docker": {Enabled: true, Port: 29375}, "http": {Enabled: true, Port: 29080},
			"postgres": {Enabled: true, Port: 29432}, "k8s": {Enabled: true, Port: 29443},
			"aws-imds": {Enabled: true, Port: 29169}, "mongo": {Enabled: true, Port: 29017},
			"elastic": {Enabled: true, Port: 29200}, "smtp": {Enabled: true, Port: 29525},
			"dns": {Enabled: true, Port: 29053}, "smb": {Enabled: true, Port: 29445},
			"telnet": {Enabled: true, Port: 29323}, "mqtt": {Enabled: true, Port: 29883},
			"modbus": {Enabled: true, Port: 29502},
		},
	}
}
