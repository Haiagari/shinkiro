package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ServiceConfig defines individual decoy listener settings
type ServiceConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Port    int  `yaml:"port" json:"port"`
}

// Config defines the global runtime parameters for Shinkiro
type Config struct {
	NodeName       string                   `yaml:"node_name" json:"node_name"`
	IdleTimeout    time.Duration            `yaml:"idle_timeout" json:"idle_timeout"`
	MaxConnections int                      `yaml:"max_connections" json:"max_connections"`
	AuditLogPath   string                   `yaml:"audit_log_path" json:"audit_log_path"`
	MetricsPort    int                      `yaml:"metrics_port" json:"metrics_port"`
	Services       map[string]ServiceConfig `yaml:"services" json:"services"`
}

// DefaultConfig provides secure zero-trust baseline settings
func DefaultConfig() *Config {
	return &Config{
		NodeName:       "shinkiro-decoy-01",
		IdleTimeout:    30 * time.Second,
		MaxConnections: 1000,
		AuditLogPath:   "data/events.jsonl",
		MetricsPort:    9100,
		Services: map[string]ServiceConfig{
			"ssh":      {Enabled: true, Port: 2222},
			"redis":    {Enabled: true, Port: 6379},
			"docker":   {Enabled: true, Port: 2375},
			"http":     {Enabled: true, Port: 8080},
			"postgres": {Enabled: true, Port: 5432},
			"k8s":      {Enabled: true, Port: 6443},
			"aws-imds": {Enabled: true, Port: 8169},
			"mongo":    {Enabled: true, Port: 27017},
			"elastic":  {Enabled: true, Port: 9200},
			"smtp":     {Enabled: true, Port: 2525},
			"dns":      {Enabled: true, Port: 1053},
			"smb":      {Enabled: true, Port: 4445},
			"telnet":   {Enabled: true, Port: 2323},
			"mqtt":     {Enabled: true, Port: 1883},
		},
	}
}

// LoadConfig reads config file or returns defaults
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = "config.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
