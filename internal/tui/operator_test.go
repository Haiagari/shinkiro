package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/Haiagari/shinkiro/internal/canary"
	"github.com/Haiagari/shinkiro/internal/defense"
	"github.com/Haiagari/shinkiro/internal/intel"
	"github.com/Haiagari/shinkiro/internal/pcap"
	"github.com/Haiagari/shinkiro/internal/soar"
)

func sampleEvents() []intel.Event {
	return []intel.Event{
		{RemoteIP: "192.0.2.10", ThreatScore: 90, DecoyName: "ssh", Action: "LOGIN", Timestamp: time.Unix(100, 0).UTC(), Severity: intel.SeverityCritical, LocalPort: 2222},
		{RemoteIP: "198.51.100.2", ThreatScore: 40, DecoyName: "http", Action: "GET", Timestamp: time.Unix(200, 0).UTC(), Severity: intel.SeverityLow, LocalPort: 8080},
		{RemoteIP: "203.0.113.5", ThreatScore: 75, DecoyName: "redis", Action: "CONFIG", Timestamp: time.Unix(150, 0).UTC(), Severity: intel.SeverityHigh, LocalPort: 6379},
	}
}

func TestHighScoreEvents(t *testing.T) {
	out := HighScoreEvents(sampleEvents(), 50, 10)
	if len(out) != 2 {
		t.Fatalf("want 2 high-score events, got %d", len(out))
	}
	if out[0].ThreatScore != 90 || out[1].ThreatScore != 75 {
		t.Fatalf("expected score order 90 then 75, got %d %d", out[0].ThreatScore, out[1].ThreatScore)
	}
}

func TestSortCampaignsByScore(t *testing.T) {
	camps := []*intel.Campaign{
		{AttackerIP: "1.1.1.1", MaxThreatScore: 10, LastSeen: time.Unix(1, 0)},
		{AttackerIP: "2.2.2.2", MaxThreatScore: 99, LastSeen: time.Unix(2, 0)},
	}
	out := SortCampaignsByScore(camps)
	if out[0].AttackerIP != "2.2.2.2" {
		t.Fatalf("expected highest score first, got %s", out[0].AttackerIP)
	}
}

func TestDispatchBlock_DryRun(t *testing.T) {
	var ran int
	blocker := soar.NewBlockApplier(soar.BlockApplierConfig{
		Mode:   soar.ApplyDryRun,
		Format: defense.FormatIPTables,
		Runner: func(name string, args []string, stdin string) error {
			ran++
			return nil
		},
	})
	m := NewModel(Config{Blocker: blocker})
	m.events = []intel.Event{{RemoteIP: "192.0.2.55", ThreatScore: 88}}
	m.cursor = 0
	res := m.DispatchBlock()
	if !res.OK {
		t.Fatalf("expected OK: %s", res.Status)
	}
	if !strings.Contains(res.Status, "dry-run") {
		t.Fatalf("status should mention dry-run: %s", res.Status)
	}
	if ran != 0 {
		t.Fatalf("runner must not run in dry-run, got %d", ran)
	}
}

func TestDispatchBlock_NoSelection(t *testing.T) {
	m := NewModel(Config{Blocker: soar.NewBlockApplier(soar.BlockApplierConfig{Mode: soar.ApplyDryRun})})
	res := m.DispatchBlock()
	if res.OK {
		t.Fatal("expected failure without selection")
	}
}

func TestDispatchPCAP_OperatorCapture(t *testing.T) {
	dir := t.TempDir()
	hook := pcap.NewOnDemandCapture(80, dir)
	defer hook.Close()
	m := NewModel(Config{PCAP: hook})
	m.events = []intel.Event{{
		RemoteIP:    "198.51.100.77",
		ThreatScore: 10, // below auto threshold — CaptureNow must still write
		Timestamp:   time.Now().UTC(),
		DecoyName:   "ssh",
	}}
	res := m.DispatchPCAP()
	if !res.OK {
		t.Fatalf("pcap failed: %s", res.Status)
	}
	if !strings.Contains(res.Status, "pcap") {
		t.Fatalf("unexpected status: %s", res.Status)
	}
}

func TestDispatchCanary(t *testing.T) {
	m := NewModel(Config{
		CanaryFn: func(label string) canary.Token {
			return canary.Token{KeyID: "AKIATESTKEY000000001", Label: label}
		},
	})
	res := m.DispatchCanary()
	if !res.OK || !strings.Contains(res.Status, "AKIATESTKEY000000001") {
		t.Fatalf("canary status: %s", res.Status)
	}
}

func TestHandleKey_BlockAndClear(t *testing.T) {
	blocker := soar.NewBlockApplier(soar.BlockApplierConfig{
		Mode:   soar.ApplyDryRun,
		Format: defense.FormatNFTables,
	})
	m := NewModel(Config{Blocker: blocker})
	m.events = []intel.Event{{RemoteIP: "203.0.113.9", ThreatScore: 70}}

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	if cmd != nil {
		t.Fatal("block should not return async cmd")
	}
	mod := next.(Model)
	if !strings.Contains(mod.status, "dry-run") {
		t.Fatalf("expected dry-run status, got %q", mod.status)
	}

	next, _ = mod.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	mod = next.(Model)
	if mod.status != "" {
		t.Fatalf("clear should empty status, got %q", mod.status)
	}
}

func TestHandleKey_HelpToggleAndTab(t *testing.T) {
	m := NewModel(Config{})
	m.events = []intel.Event{{RemoteIP: "192.0.2.1"}}
	m.campaigns = []*intel.Campaign{{AttackerIP: "192.0.2.1", MaxThreatScore: 60}}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	mod := next.(Model)
	if !mod.help {
		t.Fatal("help should open")
	}
	v := mod.View()
	if !strings.Contains(v, "OPERATOR KEYBINDINGS") {
		t.Fatal("help view missing keybindings")
	}

	next, _ = mod.Update(tea.KeyMsg{Type: tea.KeyTab})
	mod = next.(Model)
	// help still open; tab still updates focus underneath
	if mod.focus != FocusCampaigns {
		t.Fatalf("tab should switch to campaigns, got %v", mod.focus)
	}
}

func TestHandleKey_SimulateAsync(t *testing.T) {
	m := NewModel(Config{
		SimulateHost: "127.0.0.1",
		SimulateFn: func(host string) (string, error) {
			return "simulate stub ok vs " + host, nil
		},
	})
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	mod := next.(Model)
	if !strings.Contains(mod.status, "running") {
		t.Fatalf("expected running status, got %q", mod.status)
	}
	if cmd == nil {
		t.Fatal("simulate must return tea.Cmd")
	}
	msg := cmd()
	done, ok := msg.(simulateDoneMsg)
	if !ok {
		t.Fatalf("expected simulateDoneMsg, got %T", msg)
	}
	if !strings.Contains(done.Status, "simulate stub ok") {
		t.Fatalf("unexpected done status: %s", done.Status)
	}
}

func TestHelpTextDocumentsGuards(t *testing.T) {
	if !strings.Contains(HelpText, "SHINKIRO_SOAR_APPLY") {
		t.Fatal("help must document SOAR apply env guard")
	}
	if !strings.Contains(HelpText, "dry-run") {
		t.Fatal("help must mention dry-run")
	}
	if strings.Contains(strings.ToLower(HelpText), "live ebpf map") {
		t.Fatal("help must not claim live eBPF maps")
	}
}
