package intel

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Campaign represents a clustered adversary campaign across multiple decoys and protocols.
// Grouping is deterministic and rule-based (same source IP within a sliding time window,
// with multi-decoy hop tracking). This is not machine learning.
type Campaign struct {
	ID             string            `json:"id"`
	AttackerIP     string            `json:"attacker_ip"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	DecoysTargeted []string          `json:"decoys_targeted"`
	HopPath        []string          `json:"hop_path,omitempty"` // ordered decoy visits (incl. repeats)
	EventIDs       []string          `json:"event_ids,omitempty"`
	Actions        []string          `json:"actions,omitempty"`
	TotalEvents    int               `json:"total_events"`
	MaxThreatScore int               `json:"max_threat_score"`
	MitreTacticIDs []string          `json:"mitre_tactic_ids"`
	TechniqueIDs   []string          `json:"technique_ids,omitempty"`
	UsernamesUsed  []string          `json:"usernames_used,omitempty"`
	CommandsRun    []string          `json:"commands_run,omitempty"`
	Grouping       []string          `json:"grouping,omitempty"` // honest reasons events were joined
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Correlator tracks multi-protocol campaigns in memory with sliding-window clustering.
// v2 adds decoy-hop path tracking, technique IDs, event/action rolls, and clear grouping reasons.
type Correlator struct {
	mu            sync.Mutex
	campaigns     map[string]*Campaign // Key: Attacker IP
	sessionWindow time.Duration
}

func NewCorrelator(sessionWindow time.Duration) *Correlator {
	if sessionWindow <= 0 {
		sessionWindow = 2 * time.Hour
	}
	return &Correlator{
		campaigns:     make(map[string]*Campaign),
		sessionWindow: sessionWindow,
	}
}

// Ingest updates or generates a campaign based on an incoming event.
// Grouping keys: (1) same RemoteIP (2) within sessionWindow of LastSeen (3) decoy hop append.
func (c *Correlator) Ingest(ev Event) *Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()

	camp, exists := c.campaigns[ev.RemoteIP]
	expired := exists && !camp.LastSeen.IsZero() && ev.Timestamp.Sub(camp.LastSeen) > c.sessionWindow
	if !exists || expired {
		camp = &Campaign{
			ID:             fmt.Sprintf("camp-%s-%d", ev.RemoteIP, ev.Timestamp.Unix()),
			AttackerIP:     ev.RemoteIP,
			FirstSeen:      ev.Timestamp,
			LastSeen:       ev.Timestamp,
			DecoysTargeted: []string{},
			HopPath:        []string{},
			EventIDs:       []string{},
			Actions:        []string{},
			TotalEvents:    0,
			MaxThreatScore: 0,
			MitreTacticIDs: make([]string, 0),
			TechniqueIDs:   make([]string, 0),
			UsernamesUsed:  make([]string, 0),
			CommandsRun:    make([]string, 0),
			Grouping:       []string{"same_src_ip", "session_window"},
			Metadata:       make(map[string]string),
		}
		c.campaigns[ev.RemoteIP] = camp
	}

	camp.LastSeen = ev.Timestamp
	camp.TotalEvents++
	if ev.ThreatScore > camp.MaxThreatScore {
		camp.MaxThreatScore = ev.ThreatScore
	}

	if ev.DecoyName != "" {
		if !contains(camp.DecoysTargeted, ev.DecoyName) {
			camp.DecoysTargeted = append(camp.DecoysTargeted, ev.DecoyName)
			if len(camp.DecoysTargeted) > 1 && !contains(camp.Grouping, "decoy_hop") {
				camp.Grouping = append(camp.Grouping, "decoy_hop")
			}
		}
		// Hop path records ordered visits (collapse consecutive duplicates).
		if len(camp.HopPath) == 0 || camp.HopPath[len(camp.HopPath)-1] != ev.DecoyName {
			camp.HopPath = append(camp.HopPath, ev.DecoyName)
		}
	}

	if ev.ID != "" && !contains(camp.EventIDs, ev.ID) {
		camp.EventIDs = append(camp.EventIDs, ev.ID)
	}
	if ev.Action != "" && !contains(camp.Actions, ev.Action) {
		camp.Actions = append(camp.Actions, ev.Action)
	}

	if ev.Mitre != nil {
		if ev.Mitre.TacticID != "" && !contains(camp.MitreTacticIDs, ev.Mitre.TacticID) {
			camp.MitreTacticIDs = append(camp.MitreTacticIDs, ev.Mitre.TacticID)
		}
		if ev.Mitre.TechniqueID != "" && !contains(camp.TechniqueIDs, ev.Mitre.TechniqueID) {
			camp.TechniqueIDs = append(camp.TechniqueIDs, ev.Mitre.TechniqueID)
		}
	}

	if ev.Username != "" && !contains(camp.UsernamesUsed, ev.Username) {
		camp.UsernamesUsed = append(camp.UsernamesUsed, ev.Username)
	}

	if ev.Command != "" && !contains(camp.CommandsRun, ev.Command) {
		camp.CommandsRun = append(camp.CommandsRun, ev.Command)
	}

	for k, v := range ev.Metadata {
		camp.Metadata[k] = v
	}

	camp.Metadata["session_window"] = c.sessionWindow.String()
	camp.Metadata["hop_count"] = fmt.Sprintf("%d", len(camp.HopPath))
	camp.Metadata["unique_decoys"] = fmt.Sprintf("%d", len(camp.DecoysTargeted))
	camp.Metadata["grouping_note"] = "rule-based: same src IP + sliding time window + decoy hop path (not ML)"

	return camp
}

// ActiveCampaigns returns all currently tracked campaigns (unsorted).
func (c *Correlator) ActiveCampaigns() []*Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([]*Campaign, 0, len(c.campaigns))
	for _, camp := range c.campaigns {
		result = append(result, camp)
	}
	return result
}

// ActiveCampaignsSorted returns campaigns by MaxThreatScore desc, then LastSeen desc.
func (c *Correlator) ActiveCampaignsSorted() []*Campaign {
	result := c.ActiveCampaigns()
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].MaxThreatScore == result[j].MaxThreatScore {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		return result[i].MaxThreatScore > result[j].MaxThreatScore
	})
	return result
}

// CampaignByIP returns the active campaign for an attacker IP, if any.
func (c *Correlator) CampaignByIP(ip string) (*Campaign, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	camp, ok := c.campaigns[ip]
	return camp, ok
}

// PruneExpired drops campaigns whose LastSeen is older than the session window relative to now.
func (c *Correlator) PruneExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for ip, camp := range c.campaigns {
		if now.Sub(camp.LastSeen) > c.sessionWindow {
			delete(c.campaigns, ip)
			removed++
		}
	}
	return removed
}

// SummaryLine is a one-line CLI/TUI friendly description.
func (camp *Campaign) SummaryLine() string {
	if camp == nil {
		return ""
	}
	hops := strings.Join(camp.HopPath, "->")
	if hops == "" {
		hops = strings.Join(camp.DecoysTargeted, ",")
	}
	tech := strings.Join(camp.TechniqueIDs, ",")
	if tech == "" {
		tech = "-"
	}
	return fmt.Sprintf("%-18s evts=%-4d max=%-3d decoys=%-2d hops=%-24s tech=%s id=%s",
		camp.AttackerIP, camp.TotalEvents, camp.MaxThreatScore, len(camp.DecoysTargeted),
		truncate(hops, 24), tech, camp.ID)
}

// FormatCampaignsTable renders a human-readable table for CLI output.
func FormatCampaignsTable(camps []*Campaign) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-18s %-5s %-6s %-7s %-24s %-20s %s\n",
		"ATTACKER_IP", "EVTS", "MAXSCR", "DECOYS", "HOP_PATH", "TECHNIQUES", "CAMPAIGN_ID"))
	b.WriteString(strings.Repeat("-", 110))
	b.WriteString("\n")
	if len(camps) == 0 {
		b.WriteString("(no active campaigns - ingest events via the mesh / pipeline)\n")
		return b.String()
	}
	for _, c := range camps {
		if c == nil {
			continue
		}
		hops := strings.Join(c.HopPath, "->")
		if hops == "" {
			hops = strings.Join(c.DecoysTargeted, ",")
		}
		tech := strings.Join(c.TechniqueIDs, ",")
		if tech == "" {
			tech = "-"
		}
		b.WriteString(fmt.Sprintf("%-18s %-5d %-6d %-7d %-24s %-20s %s\n",
			c.AttackerIP, c.TotalEvents, c.MaxThreatScore, len(c.DecoysTargeted),
			truncate(hops, 24), truncate(tech, 20), c.ID))
	}
	b.WriteString("\n# Grouping: same source IP + sliding session window + decoy hop path (rule-based, not ML).\n")
	return b.String()
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
