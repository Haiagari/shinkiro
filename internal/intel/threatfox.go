package intel

import (
	"encoding/json"
	"fmt"
	"time"
)

// ThreatFoxIoC formats high-confidence indicators for ThreatFox / AbuseIPDB feeds
type ThreatFoxIoC struct {
	ThreatType string    `json:"threat_type"` // e.g. "botnet_cc", "payload_delivery", "honeypot_probe"
	IoCType    string    `json:"ioc_type"`    // "ip:port"
	IoCValue   string    `json:"ioc_value"`
	Confidence int       `json:"confidence_level"`
	FirstSeen  time.Time `json:"first_seen"`
	Reporter   string    `json:"reporter"`
	Tags       []string  `json:"tags"`
	Reference  string    `json:"reference"`
}

// GenerateThreatFoxFeed exports malicious events into ThreatFox-ready IoC records
func GenerateThreatFoxFeed(events []Event, minScore int) ([]byte, error) {
	if minScore <= 0 {
		minScore = 75
	}

	seen := make(map[string]bool)
	var iocs []ThreatFoxIoC

	for _, ev := range events {
		if ev.ThreatScore < minScore || seen[ev.RemoteIP] {
			continue
		}
		seen[ev.RemoteIP] = true

		tags := []string{"honeypot", "shinkiro", ev.DecoyName}
		if ev.Mitre != nil {
			tags = append(tags, ev.Mitre.TechniqueID)
		}

		iocs = append(iocs, ThreatFoxIoC{
			ThreatType: "honeypot_probe",
			IoCType:    "ip:port",
			IoCValue:   fmt.Sprintf("%s:%d", ev.RemoteIP, ev.LocalPort),
			Confidence: ev.ThreatScore,
			FirstSeen:  ev.Timestamp,
			Reporter:   "shinkiro-mesh",
			Tags:       tags,
			Reference:  "https://github.com/Haiagari/shinkiro",
		})
	}

	return json.MarshalIndent(iocs, "", "  ")
}
