package intel

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEngine_RecordAndMaliciousIPs(t *testing.T) {
	tmpDir := t.TempDir()
	eventsFile := filepath.Join(tmpDir, "events.jsonl")

	engine, err := NewEngine(eventsFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ev1 := Event{
		ID:          "ev-01",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "ssh",
		RemoteIP:    "198.51.100.99",
		Severity:    SeverityCritical,
		ThreatScore: 90,
		Action:      "SSH_LOGIN_SUCCESS_DECOY",
	}

	ev2 := Event{
		ID:          "ev-02",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "http",
		RemoteIP:    "203.0.113.10",
		Severity:    SeverityLow,
		ThreatScore: 20,
		Action:      "GET /",
	}

	if err := engine.Record(ev1); err != nil {
		t.Fatalf("record ev1 failed: %v", err)
	}
	if err := engine.Record(ev2); err != nil {
		t.Fatalf("record ev2 failed: %v", err)
	}

	malicious := engine.MaliciousIPs(80)
	if len(malicious) != 1 || malicious[0] != "198.51.100.99" {
		t.Fatalf("expected only 198.51.100.99 to be malicious, got %v", malicious)
	}
}
