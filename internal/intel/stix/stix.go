package stix

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// STIXBundle represents a standard STIX 2.1 Threat Intelligence Bundle
type STIXBundle struct {
	Type        string        `json:"type"`
	ID          string        `json:"id"`
	SpecVersion string        `json:"spec_version"`
	Objects     []interface{} `json:"objects"`
}

// Indicator represents a STIX 2.1 Indicator object
type Indicator struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	SpecVersion string    `json:"spec_version"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	ValidFrom   time.Time `json:"valid_from"`
	Confidence  int       `json:"confidence"`
	Labels      []string  `json:"labels"`
}

// ConvertEventsToSTIX transforms internal Shinkiro events into a STIX 2.1 Bundle
func ConvertEventsToSTIX(events []intel.Event) ([]byte, error) {
	bundle := STIXBundle{
		Type:        "bundle",
		ID:          fmt.Sprintf("bundle--%d", time.Now().UnixNano()),
		SpecVersion: "2.1",
		Objects:     make([]interface{}, 0),
	}

	seenIPs := make(map[string]bool)

	for _, ev := range events {
		if ev.ThreatScore < 60 || seenIPs[ev.RemoteIP] {
			continue
		}
		seenIPs[ev.RemoteIP] = true

		indicator := Indicator{
			Type:        "indicator",
			ID:          fmt.Sprintf("indicator--%s", ev.ID),
			SpecVersion: "2.1",
			Created:     ev.Timestamp,
			Modified:    ev.Timestamp,
			Name:        fmt.Sprintf("Malicious Honeypot Probe from %s", ev.RemoteIP),
			Description: fmt.Sprintf("Observed %s probe on decoy port %d (%s). Threat score: %d", ev.DecoyName, ev.LocalPort, ev.Action, ev.ThreatScore),
			Pattern:     fmt.Sprintf("[ipv4-addr:value = '%s']", ev.RemoteIP),
			PatternType: "stix",
			ValidFrom:   ev.Timestamp,
			Confidence:  ev.ThreatScore,
			Labels:      []string{"malicious-activity", "honeypot", "attacker-ip"},
		}

		bundle.Objects = append(bundle.Objects, indicator)
	}

	return json.MarshalIndent(bundle, "", "  ")
}
