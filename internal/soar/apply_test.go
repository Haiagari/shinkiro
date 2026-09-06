package soar

import (
	"strings"
	"testing"

	"github.com/Haiagari/shinkiro/internal/defense"
)

func TestBlockApplier_DryRunDefault(t *testing.T) {
	var ran int
	a := NewBlockApplier(BlockApplierConfig{
		Mode:   ApplyDryRun,
		Format: defense.FormatIPTables,
		Runner: func(name string, args []string, stdin string) error {
			ran++
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
	if ran != 0 {
		t.Fatalf("runner must not be called in dry-run, got %d", ran)
	}
}

func TestBlockApplier_ApplyExecutesIPTables(t *testing.T) {
	var calls []string
	a := NewBlockApplier(BlockApplierConfig{
		Mode:   ApplyLive,
		Format: defense.FormatIPTables,
		Runner: func(name string, args []string, stdin string) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
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
	if len(calls) == 0 {
		t.Fatal("expected runner invocation")
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "iptables") || !strings.Contains(joined, "198.51.100.9") {
		t.Fatalf("unexpected runner calls: %v", calls)
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

func TestBlockApplier_NFTablesApplyUsesStdinBatch(t *testing.T) {
	var gotName string
	var gotArgs []string
	var gotStdin string
	a := NewBlockApplier(BlockApplierConfig{
		Mode:   ApplyLive,
		Format: defense.FormatNFTables,
		Runner: func(name string, args []string, stdin string) error {
			gotName = name
			gotArgs = append([]string{}, args...)
			gotStdin = stdin
			return nil
		},
	})
	res, err := a.BlockIP("203.0.113.8", "nft-apply")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("expected applied")
	}
	if gotName != "nft" || len(gotArgs) < 2 || gotArgs[0] != "-f" || gotArgs[1] != "-" {
		t.Fatalf("expected nft -f -, got %s %v", gotName, gotArgs)
	}
	if !strings.Contains(gotStdin, "203.0.113.8") || !strings.Contains(gotStdin, "{") {
		t.Fatalf("stdin must preserve braced nft script, got:\n%s", gotStdin)
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
