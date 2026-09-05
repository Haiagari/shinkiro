package intel

import (
	"encoding/json"
	"testing"
	"time"
)

func TestGenerateThreatFoxFeed(t *testing.T) {
	events := []Event{
		{
			ID:          "1",
			Timestamp:   time.Now().UTC(),
			DecoyName:   "ssh",
			RemoteIP:    "198.51.100.1",
			LocalPort:   2222,
			ThreatScore: 85,
			Mitre: &MitreAttack{
				TechniqueID: "T1110",
			},
		},
		{
			ID:          "2",
			Timestamp:   time.Now().UTC(),
			DecoyName:   "http",
			RemoteIP:    "198.51.100.2",
			LocalPort:   8080,
			ThreatScore: 40, // Low score
		},
	}

	data, err := GenerateThreatFoxFeed(events, 75)
	if err != nil {
		t.Fatalf("failed to generate feed: %v", err)
	}

	var iocs []ThreatFoxIoC
	if err := json.Unmarshal(data, &iocs); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(iocs) != 1 {
		t.Fatalf("expected exactly 1 IoC above threshold, got %d", len(iocs))
	}

	if iocs[0].IoCValue != "198.51.100.1:2222" {
		t.Errorf("expected IoCValue 198.51.100.1:2222, got %s", iocs[0].IoCValue)
	}
}
