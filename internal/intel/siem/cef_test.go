package siem

import (
	"strings"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestFormatCEF(t *testing.T) {
	ev := intel.Event{
		ID:          "test-123",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "redis",
		RemoteIP:    "192.168.1.50",
		RemotePort:  45678,
		LocalPort:   6379,
		Severity:    intel.SeverityHigh,
		ThreatScore: 75,
		Action:      "CONFIG GET",
		Command:     "CONFIG GET dir",
		Mitre: &intel.MitreAttack{
			TacticID:      "TA0002",
			TacticName:    "Execution",
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			Reference:     "https://attack.mitre.org/techniques/T1059/",
		},
	}

	cef := FormatCEF(ev, "sensor-01")

	if !strings.HasPrefix(cef, "CEF:0|Haiagari|Shinkiro|0.4.0|redis|CONFIG GET|8|") {
		t.Fatalf("unexpected CEF header: %s", cef)
	}

	if !strings.Contains(cef, "src=192.168.1.50") || !strings.Contains(cef, "dpt=6379") {
		t.Errorf("missing network fields in CEF: %s", cef)
	}

	if !strings.Contains(cef, "cs1=T1059") {
		t.Errorf("missing MITRE technique in CEF: %s", cef)
	}
}

func TestFormatSyslog(t *testing.T) {
	ev := intel.Event{
		ID:          "test-456",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "ssh",
		RemoteIP:    "10.0.0.99",
		RemotePort:  52341,
		LocalPort:   2222,
		Severity:    intel.SeverityCritical,
		ThreatScore: 90,
		Action:      "SSH_LOGIN_SUCCESS_DECOY",
		Username:    "root",
	}

	syslog := FormatSyslog(ev, "sensor-01")
	if !strings.HasPrefix(syslog, "<134>1 ") {
		t.Fatalf("expected RFC5424 syslog prefix, got: %s", syslog)
	}
	if !strings.Contains(syslog, "CEF:0|Haiagari|Shinkiro|") {
		t.Fatalf("expected CEF payload in syslog, got: %s", syslog)
	}
}
