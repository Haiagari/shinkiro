package ecs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestConvertToECS(t *testing.T) {
	now := time.Now().UTC()
	ev := intel.Event{
		ID:          "test-123",
		Timestamp:   now,
		DecoyName:   "ssh",
		RemoteIP:    "198.51.100.42",
		RemotePort:  52341,
		Severity:    intel.SeverityCritical,
		ThreatScore: 95,
		Action:      "SSH_AUTH_FAIL",
		Username:    "root",
		Metadata: map[string]string{
			"geo_country": "Netherlands",
			"geo_city":    "Amsterdam",
			"geo_asn":     "AS12345",
			"geo_org":     "Host Provider",
		},
	}

	ecsEv := ConvertToECS(ev, "sensor-us-east-1")

	if ecsEv.ECS.Version != "8.11.0" {
		t.Errorf("unexpected ECS version: %s", ecsEv.ECS.Version)
	}
	if ecsEv.Event.Severity != 10 {
		t.Errorf("expected severity 10 for critical, got %d", ecsEv.Event.Severity)
	}
	if ecsEv.Source.IP != "198.51.100.42" {
		t.Errorf("expected source IP 198.51.100.42, got %s", ecsEv.Source.IP)
	}
	if ecsEv.Source.Geo == nil || ecsEv.Source.Geo.CountryName != "Netherlands" {
		t.Errorf("expected Netherlands geo country")
	}
	if ecsEv.User == nil || ecsEv.User.Name != "root" {
		t.Errorf("expected user root")
	}

	data, err := ConvertBatchToECSJSON([]intel.Event{ev}, "sensor-01")
	if err != nil {
		t.Fatalf("failed to convert batch to JSON: %v", err)
	}

	var parsed []map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated ECS JSON: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 element, got %d", len(parsed))
	}
}
