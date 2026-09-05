package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.NodeName == "" {
		t.Fatal("expected default NodeName, got empty")
	}
	if cfg.IdleTimeout != 30*time.Second {
		t.Fatalf("expected 30s idle timeout, got %v", cfg.IdleTimeout)
	}
	if !cfg.Services["ssh"].Enabled || cfg.Services["ssh"].Port != 2222 {
		t.Fatalf("expected ssh decoy on port 2222, got %+v", cfg.Services["ssh"])
	}
	if !cfg.Services["modbus"].Enabled || cfg.Services["modbus"].Port != 502 {
		t.Fatalf("expected modbus decoy on port 502, got %+v", cfg.Services["modbus"])
	}
}

func TestLoadConfig_FallbackToDefault(t *testing.T) {
	cfg, err := LoadConfig("non_existent_config_path.yaml")
	if err != nil {
		t.Fatalf("expected fallback to default config, got err: %v", err)
	}
	if cfg.NodeName != "shinkiro-decoy-01" {
		t.Fatalf("expected default node name, got %s", cfg.NodeName)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "shinkiro-test-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
node_name: "custom-decoy-test"
idle_timeout: 15s
max_connections: 500
audit_log_path: "logs/test.jsonl"
metrics_port: 9200
services:
  ssh:
    enabled: true
    port: 22222
`
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write config content: %v", err)
	}
	tmpFile.Close()

	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}
	if cfg.NodeName != "custom-decoy-test" {
		t.Fatalf("expected custom node name, got %s", cfg.NodeName)
	}
	if cfg.Services["ssh"].Port != 22222 {
		t.Fatalf("expected port 22222, got %d", cfg.Services["ssh"].Port)
	}
}
