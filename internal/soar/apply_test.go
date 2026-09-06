package soar

import (
	"strings"
	"testing"

	"github.com/Haiagari/shinkiro/internal/defense"
)

func TestBlockApplier_DryRunDefault(t *testing.T) {
	var ran []string
	a := NewBlockApplier(BlockApplierConfig{
		Mode:   ApplyDryRun,
		Format: defense.FormatIPTables,
		Runner: func(name string, args ...string) error {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return nil
		},
	})

	res, err := a.BlockIP("192.0.2.50", "unit-test")
	if err != nil {
		t.Fatalf("dry-run error: %v", err)
	}
	if res.Applied {
		t.Fatal("dry-run must not set Applied=true")
	}
	if res.Mode != ApplyDryRun {
		t.Fatalf("mode=%s", res.Mode)
	}
	if !strings.Contains(res.Commands, "iptables") || !strings.Contains(res.Commands, "192.0.2.50") {
		t.Fatalf("expected iptables command for IP, got:\n%s", res.Commands)
	}
	if !strings.Contains(res.Message, "dry-run") {
		t.Fatalf("message should mention dry-run: %s", res.Message)
	}
	if len(ran) != 0 {
		t.Fatalf("runner must not be called in dry-run, got %v", ran)
	}
}

func TestBlockApplier_ApplyExecutesIPTables(t *testing.T) {
	var ran []string
	a := NewBlockApplier(BlockApplierConfig{
		Mode:   ApplyLive,
		Format: defense.FormatIPTables,
		Runner: func(name string, args ...string) error {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return nil
		},
	})

	res, err := a.BlockIP("198.51.100.9", "soar-rule")
	if err != nil {
		t.Fatalf("apply error: %v", err)
	}
	if !res.Applied {
		t.Fatal("expected Applied=true")
	}
	if len(ran) == 0 {
		t.Fatal("expected runner invocation")
	}
	joined := strings.Join(ran, "\n")
	if !strings.Contains(joined, "iptables") || !strings.Contains(joined, "198.51.100.9") {
		t.Fatalf("unexpected runner calls: %v", ran)
	}
}

func TestBlockApplier_NFTablesDryRunOutput(t *testing.T) {
	a := NewBlockApplier(BlockApplierConfig{
		Mode:   ApplyDryRun,
		Format: defense.FormatNFTables,
	})
	res, err := a.BlockIP("203.0.113.7", "nft-test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Commands, "shinkiro_filter") {
		t.Fatalf("expected nftables table text, got:\n%s", res.Commands)
	}
	if !strings.Contains(res.Commands, "203.0.113.7") {
		t.Fatalf("IP missing from commands:\n%s", res.Commands)
	}
}

func TestModeFromEnv(t *testing.T) {
	t.Setenv("SHINKIRO_SOAR_APPLY", "")
	if ModeFromEnv() != ApplyDryRun {
		t.Fatal("empty env must be dry-run")
	}
	t.Setenv("SHINKIRO_SOAR_APPLY", "1")
	if ModeFromEnv() != ApplyLive {
		t.Fatal("SHINKIRO_SOAR_APPLY=1 must enable apply")
	}
	t.Setenv("SHINKIRO_SOAR_APPLY", "true")
	if ModeFromEnv() != ApplyDryRun {
		t.Fatal("only literal 1 enables apply")
	}
}
