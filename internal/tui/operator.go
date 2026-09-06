package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/adversary"
	"github.com/Haiagari/shinkiro/internal/canary"
	"github.com/Haiagari/shinkiro/internal/intel"
)

// FocusPane selects which list receives cursor navigation.
type FocusPane int

const (
	FocusEvents FocusPane = iota
	FocusCampaigns
)

// ActionResult is a testable outcome from an operator dispatch (no terminal I/O).
type ActionResult struct {
	Status string
	OK     bool
}

// HighScoreEvents returns events with ThreatScore >= minScore, highest score first, capped at limit.
func HighScoreEvents(events []intel.Event, minScore, limit int) []intel.Event {
	var out []intel.Event
	for _, ev := range events {
		if ev.ThreatScore >= minScore {
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ThreatScore == out[j].ThreatScore {
			return out[i].Timestamp.After(out[j].Timestamp)
		}
		return out[i].ThreatScore > out[j].ThreatScore
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// SortCampaignsByScore returns a copy of campaigns sorted by MaxThreatScore descending.
func SortCampaignsByScore(camps []*intel.Campaign) []*intel.Campaign {
	out := make([]*intel.Campaign, len(camps))
	copy(out, camps)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MaxThreatScore == out[j].MaxThreatScore {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].MaxThreatScore > out[j].MaxThreatScore
	})
	return out
}

// SelectedIP returns the attacker IP for the current pane/cursor, or empty.
func (m Model) SelectedIP() string {
	switch m.focus {
	case FocusCampaigns:
		if m.cursor >= 0 && m.cursor < len(m.campaigns) && m.campaigns[m.cursor] != nil {
			return m.campaigns[m.cursor].AttackerIP
		}
	default:
		if m.cursor >= 0 && m.cursor < len(m.events) {
			return m.events[m.cursor].RemoteIP
		}
	}
	return ""
}

// SelectedEvent builds an intel.Event for operator actions from the current selection.
func (m Model) SelectedEvent() (intel.Event, bool) {
	switch m.focus {
	case FocusCampaigns:
		if m.cursor >= 0 && m.cursor < len(m.campaigns) && m.campaigns[m.cursor] != nil {
			c := m.campaigns[m.cursor]
			decoy := ""
			if len(c.DecoysTargeted) > 0 {
				decoy = c.DecoysTargeted[0]
			}
			return intel.Event{
				ID:          c.ID,
				Timestamp:   time.Now().UTC(),
				DecoyName:   decoy,
				RemoteIP:    c.AttackerIP,
				ThreatScore: c.MaxThreatScore,
				Action:      "operator-campaign",
				Severity:    intel.SeverityHigh,
			}, c.AttackerIP != ""
		}
	default:
		if m.cursor >= 0 && m.cursor < len(m.events) {
			ev := m.events[m.cursor]
			return ev, ev.RemoteIP != ""
		}
	}
	return intel.Event{}, false
}

// DispatchBlock triggers SOAR block_ip via BlockApplier (dry-run unless ApplyLive mode).
func (m *Model) DispatchBlock() ActionResult {
	if m.cfg.Blocker == nil {
		return ActionResult{Status: "block_ip unavailable: no SOAR BlockApplier wired", OK: false}
	}
	ip := m.SelectedIP()
	if ip == "" {
		return ActionResult{Status: "block_ip: no IP selected", OK: false}
	}
	res, err := m.cfg.Blocker.BlockIP(ip, "tui-operator")
	if err != nil {
		return ActionResult{Status: fmt.Sprintf("block_ip error: %v", err), OK: false}
	}
	mode := string(res.Mode)
	if res.Applied {
		return ActionResult{Status: fmt.Sprintf("block_ip LIVE applied %s (%s)", ip, mode), OK: true}
	}
	return ActionResult{
		Status: fmt.Sprintf("block_ip dry-run %s — %s", ip, shortMsg(res.Message, 80)),
		OK:     true,
	}
}

// DispatchPCAP triggers operator on-demand PCAP for the selection.
func (m *Model) DispatchPCAP() ActionResult {
	if m.cfg.PCAP == nil {
		return ActionResult{Status: "pcap unavailable: OnDemandCapture not wired", OK: false}
	}
	ev, ok := m.SelectedEvent()
	if !ok {
		return ActionResult{Status: "pcap: no IP/event selected", OK: false}
	}
	res, err := m.cfg.PCAP.CaptureNow(ev)
	if err != nil {
		return ActionResult{Status: fmt.Sprintf("pcap error: %v", err), OK: false}
	}
	if !res.Triggered || res.Path == "" {
		return ActionResult{Status: "pcap: capture did not write a file", OK: false}
	}
	return ActionResult{
		Status: fmt.Sprintf("pcap operator capture %s → %s (score=%d)", ev.RemoteIP, res.Path, ev.ThreatScore),
		OK:     true,
	}
}

// DispatchCanary generates an AWS honeytoken and returns a short status.
func (m *Model) DispatchCanary() ActionResult {
	label := "tui-operator"
	if m.cfg.CanaryLabel != "" {
		label = m.cfg.CanaryLabel
	}
	var token canary.Token
	if m.cfg.CanaryFn != nil {
		token = m.cfg.CanaryFn(label)
	} else {
		token = canary.GenerateAWSKey(label)
	}
	return ActionResult{
		Status: fmt.Sprintf("canary AWS key_id=%s label=%s (place as honeytoken — not live IAM)", token.KeyID, token.Label),
		OK:     true,
	}
}

// RunSimulateSync runs the default adversary suite (blocking). Prefer tea.Cmd wrapper in Update.
func RunSimulateSync(host string, simulateFn func(string) (string, error)) ActionResult {
	if host == "" {
		host = "127.0.0.1"
	}
	if simulateFn != nil {
		msg, err := simulateFn(host)
		if err != nil {
			return ActionResult{Status: fmt.Sprintf("simulate error: %v", err), OK: false}
		}
		return ActionResult{Status: msg, OK: true}
	}
	sim := adversary.NewSimulator(host, 1500*time.Millisecond)
	scenarios := adversary.DefaultScenarios()
	ok, fail := 0, 0
	for _, sc := range scenarios {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_, err := sim.RunScenario(ctx, sc)
		cancel()
		if err != nil {
			fail++
		} else {
			ok++
		}
	}
	return ActionResult{
		Status: fmt.Sprintf("simulate vs %s: %d ok / %d failed of %d scenarios (mesh must be listening)", host, ok, fail, len(scenarios)),
		OK:     true,
	}
}

// RefreshFromStore loads high-score events and campaigns from the intel engine/correlator.
func (m *Model) RefreshFromStore() ActionResult {
	if m.cfg.Engine == nil {
		return ActionResult{Status: "refresh: no intel Engine wired — live feed only", OK: false}
	}
	minScore := m.cfg.MinScore
	if minScore <= 0 {
		minScore = 50
	}
	raw := m.cfg.Engine.RecentEvents(200)
	m.events = HighScoreEvents(raw, minScore, 15)
	if m.cfg.Engine.Correlator != nil {
		m.campaigns = SortCampaignsByScore(m.cfg.Engine.Correlator.ActiveCampaigns())
		if len(m.campaigns) > 15 {
			m.campaigns = m.campaigns[:15]
		}
	}
	m.clampCursor()
	return ActionResult{
		Status: fmt.Sprintf("refreshed: %d high-score events (≥%d), %d campaigns", len(m.events), minScore, len(m.campaigns)),
		OK:     true,
	}
}

func (m *Model) clampCursor() {
	max := 0
	switch m.focus {
	case FocusCampaigns:
		max = len(m.campaigns) - 1
	default:
		max = len(m.events) - 1
	}
	if max < 0 {
		m.cursor = 0
		return
	}
	if m.cursor > max {
		m.cursor = max
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m *Model) moveCursor(delta int) {
	m.cursor += delta
	m.clampCursor()
}

func shortMsg(s string, n int) string {
	s = strings.TrimSpace(s)
	if n > 0 && len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
