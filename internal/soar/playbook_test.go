package soar

import (
	"testing"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestSOAR_EngineExecution(t *testing.T) {
	eng := NewEngine()

	var blockedLog []string
	eng.SetBlockHook(func(ip, reason string) error {
		blockedLog = append(blockedLog, ip)
		return nil
	})

	// Rule 1: High severity SSH brute force -> block
	eng.AddRule(Rule{
		Name:    "ssh-bruteforce-autoblock",
		Enabled: true,
		If: Condition{
			Decoy:       "ssh",
			ActionMatch: "LOGIN",
			MinScore:    70,
		},
		Then: []Action{
			{Type: "block_ip"},
			{Type: "alert"},
		},
	})

	evMatch := intel.Event{
		DecoyName:   "ssh",
		Action:      "SSH_LOGIN_SUCCESS_DECOY",
		RemoteIP:    "192.0.2.1",
		ThreatScore: 75,
	}

	actions := eng.Process(evMatch)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions executed, got %d: %v", len(actions), actions)
	}

	if len(blockedLog) != 1 || blockedLog[0] != "192.0.2.1" {
		t.Fatalf("expected block hook for 192.0.2.1, got: %v", blockedLog)
	}

	// Non-matching event
	evNoMatch := intel.Event{
		DecoyName:   "redis",
		Action:      "PING",
		RemoteIP:    "192.0.2.2",
		ThreatScore: 10,
	}

	actions2 := eng.Process(evNoMatch)
	if len(actions2) != 0 {
		t.Errorf("expected 0 actions for benign event, got %d", len(actions2))
	}
}

func TestSOAR_ThresholdRateWindow(t *testing.T) {
	eng := NewEngine()

	// Rule: 3 failed attacks within 60 seconds
	eng.AddRule(Rule{
		Name:    "rapid-redis-probe",
		Enabled: true,
		If: Condition{
			Decoy:     "redis",
			Threshold: 3,
			WindowSec: 60,
		},
		Then: []Action{
			{Type: "block_ip"},
		},
	})

	ev := intel.Event{
		DecoyName:   "redis",
		Action:      "INFO",
		RemoteIP:    "10.10.10.5",
		ThreatScore: 50,
	}

	// 1st event -> not triggered
	res1 := eng.Process(ev)
	if len(res1) != 0 {
		t.Errorf("expected no action on 1st event, got %v", res1)
	}

	// 2nd event -> not triggered
	res2 := eng.Process(ev)
	if len(res2) != 0 {
		t.Errorf("expected no action on 2nd event, got %v", res2)
	}

	// 3rd event -> triggers
	res3 := eng.Process(ev)
	if len(res3) != 1 {
		t.Fatalf("expected action on 3rd event, got %v", res3)
	}

	blocked := eng.BlockedIPs()
	if len(blocked) != 1 || blocked[0] != "10.10.10.5" {
		t.Fatalf("expected blocked IP 10.10.10.5, got %v", blocked)
	}
}
