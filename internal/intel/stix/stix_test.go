package stix

import (
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestConvertEventsToSTIX(t *testing.T) {
	events := []intel.Event{
		{
			ID:          "ev-991",
			Timestamp:   time.Now().UTC(),
			DecoyName:   "ssh",
			RemoteIP:    "198.51.100.88",
			LocalPort:   2222,
			Severity:    intel.SeverityCritical,
			ThreatScore: 90,
			Action:      "SSH_BRUTE_FORCE",
		},
	}

	data, err := ConvertEventsToSTIX(events)
	if err != nil {
		t.Fatalf("unexpected conversion error: %v", err)
	}

	out := string(data)
	if !strings.Contains(out, "\"spec_version\": \"2.1\"") {
		t.Errorf("expected STIX 2.1 spec version, got: %s", out)
	}
	if !strings.Contains(out, "198.51.100.88") {
		t.Errorf("expected IP in STIX pattern: %s", out)
	}
}
