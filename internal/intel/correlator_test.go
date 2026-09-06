package intel

import (
	"fmt"
	"strings"
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
			TacticID:    "TA0006",
			TechniqueID: "T1110",
		},
	}
	c1 := c.Ingest(ev1)
	if c1.TotalEvents != 1 || len(c1.DecoysTargeted) != 1 {
		t.Fatalf("expected 1 event and 1 decoy, got %d and %d", c1.TotalEvents, len(c1.DecoysTargeted))
	}
	if len(c1.HopPath) != 1 || c1.HopPath[0] != "ssh" {
		t.Fatalf("expected hop path [ssh], got %v", c1.HopPath)
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
			TacticID:    "TA0002",
			TechniqueID: "T1059",
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
	if len(c2.TechniqueIDs) != 2 {
		t.Errorf("expected 2 technique IDs, got %v", c2.TechniqueIDs)
	}
	if !contains(c2.Grouping, "decoy_hop") {
		t.Errorf("expected decoy_hop in grouping reasons, got %v", c2.Grouping)
	}
	if strings.Join(c2.HopPath, "->") != "ssh->redis" {
		t.Errorf("expected hop path ssh->redis, got %v", c2.HopPath)
	}
}

func TestCorrelator_SessionWindowExpiry(t *testing.T) {
	c := NewCorrelator(10 * time.Minute)
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	c.Ingest(Event{
		ID: "a1", Timestamp: now, RemoteIP: "203.0.113.9",
		DecoyName: "ssh", Action: "LOGIN", ThreatScore: 50,
	})
	c2 := c.Ingest(Event{
		ID: "a2", Timestamp: now.Add(30 * time.Minute), RemoteIP: "203.0.113.9",
		DecoyName: "http", Action: "GET", ThreatScore: 40,
	})
	if c2.TotalEvents != 1 {
		t.Fatalf("expected new campaign after window expiry, got TotalEvents=%d id=%s", c2.TotalEvents, c2.ID)
	}
}

func TestCorrelator_HopPathCollapsesConsecutive(t *testing.T) {
	c := NewCorrelator(time.Hour)
	now := time.Now()
	ip := "198.51.100.50"
	for i, decoy := range []string{"ssh", "ssh", "redis", "redis", "modbus"} {
		c.Ingest(Event{
			ID: fmt.Sprintf("ev-%d", i), Timestamp: now.Add(time.Duration(i) * time.Minute),
			RemoteIP: ip, DecoyName: decoy, Action: "PROBE", ThreatScore: 60 + i,
		})
	}
	camp, ok := c.CampaignByIP(ip)
	if !ok {
		t.Fatal("expected campaign")
	}
	got := strings.Join(camp.HopPath, "->")
	want := "ssh->redis->modbus"
	if got != want {
		t.Fatalf("hop path: got %q want %q", got, want)
	}
	if len(camp.DecoysTargeted) != 3 {
		t.Fatalf("unique decoys: got %v", camp.DecoysTargeted)
	}
}

func TestCorrelator_PruneExpired(t *testing.T) {
	c := NewCorrelator(15 * time.Minute)
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	c.Ingest(Event{ID: "old", Timestamp: now.Add(-time.Hour), RemoteIP: "198.51.100.1", DecoyName: "ssh", ThreatScore: 10})
	c.Ingest(Event{ID: "new", Timestamp: now, RemoteIP: "198.51.100.2", DecoyName: "redis", ThreatScore: 20})
	removed := c.PruneExpired(now)
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
	if _, ok := c.CampaignByIP("198.51.100.1"); ok {
		t.Fatal("old campaign should be gone")
	}
	if _, ok := c.CampaignByIP("198.51.100.2"); !ok {
		t.Fatal("fresh campaign should remain")
	}
}

func TestFormatCampaignsTable(t *testing.T) {
	c := NewCorrelator(time.Hour)
	now := time.Now()
	c.Ingest(Event{
		ID: "e1", Timestamp: now, RemoteIP: "198.51.100.7", DecoyName: "ssh",
		Action: "LOGIN", ThreatScore: 80,
		Mitre: &MitreAttack{TacticID: "TA0006", TechniqueID: "T1110"},
	})
	c.Ingest(Event{
		ID: "e2", Timestamp: now.Add(time.Minute), RemoteIP: "198.51.100.7", DecoyName: "telnet",
		Action: "LOGIN", ThreatScore: 70,
		Mitre: &MitreAttack{TacticID: "TA0006", TechniqueID: "T1078"},
	})
	out := FormatCampaignsTable(c.ActiveCampaignsSorted())
	if !strings.Contains(out, "198.51.100.7") {
		t.Fatalf("table missing IP:\n%s", out)
	}
	if !strings.Contains(out, "ssh->telnet") {
		t.Fatalf("table missing hop path:\n%s", out)
	}
	if !strings.Contains(out, "rule-based") {
		t.Fatalf("table missing honesty note:\n%s", out)
	}
}
