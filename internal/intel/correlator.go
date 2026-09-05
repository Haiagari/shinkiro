package intel

import (
	"fmt"
	"sync"
	"time"
)

// Campaign represents a clustered adversary campaign across multiple decoys and protocols
type Campaign struct {
	ID             string            `json:"id"`
	AttackerIP     string            `json:"attacker_ip"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	DecoysTargeted []string          `json:"decoys_targeted"`
	TotalEvents    int               `json:"total_events"`
	MaxThreatScore int               `json:"max_threat_score"`
	MitreTacticIDs []string          `json:"mitre_tactic_ids"`
	UsernamesUsed  []string          `json:"usernames_used,omitempty"`
	CommandsRun    []string          `json:"commands_run,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Correlator tracks multi-protocol campaigns in memory with sliding window clustering
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

// Ingest updates or generates a campaign based on incoming event
func (c *Correlator) Ingest(ev Event) *Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()

	camp, exists := c.campaigns[ev.RemoteIP]
	if !exists || time.Since(camp.LastSeen) > c.sessionWindow {
		camp = &Campaign{
			ID:             fmt.Sprintf("camp-%s-%d", ev.RemoteIP, ev.Timestamp.Unix()),
			AttackerIP:     ev.RemoteIP,
			FirstSeen:      ev.Timestamp,
			LastSeen:       ev.Timestamp,
			DecoysTargeted: []string{ev.DecoyName},
			TotalEvents:    1,
			MaxThreatScore: ev.ThreatScore,
			MitreTacticIDs: make([]string, 0),
			UsernamesUsed:  make([]string, 0),
			CommandsRun:    make([]string, 0),
			Metadata:       make(map[string]string),
		}
		c.campaigns[ev.RemoteIP] = camp
	} else {
		camp.LastSeen = ev.Timestamp
		camp.TotalEvents++
		if ev.ThreatScore > camp.MaxThreatScore {
			camp.MaxThreatScore = ev.ThreatScore
		}
		if !contains(camp.DecoysTargeted, ev.DecoyName) {
			camp.DecoysTargeted = append(camp.DecoysTargeted, ev.DecoyName)
		}
	}

	if ev.Mitre != nil && !contains(camp.MitreTacticIDs, ev.Mitre.TacticID) {
		camp.MitreTacticIDs = append(camp.MitreTacticIDs, ev.Mitre.TacticID)
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

	return camp
}

// ActiveCampaigns returns all currently active campaigns
func (c *Correlator) ActiveCampaigns() []*Campaign {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []*Campaign
	for _, camp := range c.campaigns {
		result = append(result, camp)
	}
	return result
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
