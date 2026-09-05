package intel

import (
	"testing"
	"time"
)

func TestCorrelator_CampaignClustering(t *testing.T) {
	c := NewCorrelator(1 * time.Hour)

	now := time.Now()
	// 1. Attacker hits SSH
	ev1 := Event{
		ID:          "ev1",
		Timestamp:   now,
		RemoteIP:    "198.51.100.25",
		DecoyName:   "ssh",
		Action:      "SSH_LOGIN",
		Username:    "admin",
		ThreatScore: 70,
		Mitre: &MitreAttack{
			TacticID: "TA0006",
		},
	}
	c1 := c.Ingest(ev1)
	if c1.TotalEvents != 1 || len(c1.DecoysTargeted) != 1 {
		t.Fatalf("expected 1 event and 1 decoy, got %d and %d", c1.TotalEvents, len(c1.DecoysTargeted))
	}

	// 2. Same attacker hits Redis 5 minutes later
	ev2 := Event{
		ID:          "ev2",
		Timestamp:   now.Add(5 * time.Minute),
		RemoteIP:    "198.51.100.25",
		DecoyName:   "redis",
		Action:      "CONFIG",
		Command:     "CONFIG GET *",
		ThreatScore: 90,
		Mitre: &MitreAttack{
			TacticID: "TA0002",
		},
	}
	c2 := c.Ingest(ev2)

	if c2.ID != c1.ID {
		t.Errorf("expected campaign IDs to match for same session")
	}
	if c2.TotalEvents != 2 {
		t.Errorf("expected 2 total events, got %d", c2.TotalEvents)
	}
	if len(c2.DecoysTargeted) != 2 {
		t.Errorf("expected 2 decoys targeted (ssh + redis), got %v", c2.DecoysTargeted)
	}
	if c2.MaxThreatScore != 90 {
		t.Errorf("expected max threat score 90, got %d", c2.MaxThreatScore)
	}
	if len(c2.MitreTacticIDs) != 2 {
		t.Errorf("expected 2 MITRE tactics, got %v", c2.MitreTacticIDs)
	}
}
