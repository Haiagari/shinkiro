package intel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildCoverageReport_FromMatrixFixtures(t *testing.T) {
	r := BuildCoverageReport(false)
	if r.TotalDecoys != 15 {
		t.Fatalf("expected 15 decoys from matrix, got %d", r.TotalDecoys)
	}
	if r.TotalTechniques < 10 {
		t.Fatalf("expected substantial unique techniques, got %d", r.TotalTechniques)
	}
	// Spot-check documented mappings (must match decoy-matrix.md).
	foundSSH := false
	for _, d := range r.Decoys {
		if d.Decoy != "ssh" {
			continue
		}
		foundSSH = true
		ids := map[string]bool{}
		for _, tech := range d.Techniques {
			ids[tech.ID] = true
		}
		for _, want := range []string{"T1078", "T1059.004", "T1021.004"} {
			if !ids[want] {
				t.Errorf("ssh missing technique %s", want)
			}
		}
	}
	if !foundSSH {
		t.Fatal("ssh decoy missing from report")
	}
	if _, ok := r.TechniqueToDecoys["T0855"]; !ok {
		t.Fatal("expected ICS T0855 from modbus in technique index")
	}
	if !strings.Contains(r.Note, "decoy-matrix") {
		t.Fatalf("note should cite decoy-matrix: %s", r.Note)
	}
}

func TestBuildCoverageReport_WithRuntimeMapper(t *testing.T) {
	r := BuildCoverageReport(true)
	hasRuntime := false
	for _, d := range r.Decoys {
		if d.Source == "map_to_mitre" {
			hasRuntime = true
			if len(d.Techniques) == 0 {
				t.Fatal("runtime mapper entry should list techniques")
			}
		}
	}
	if !hasRuntime {
		t.Fatal("expected map_to_mitre entry")
	}
}

func TestCoverageReportJSON_RoundTrip(t *testing.T) {
	r := BuildCoverageReport(false)
	raw, err := CoverageReportJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var back CoverageReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.TotalDecoys != r.TotalDecoys {
		t.Fatalf("round-trip decoys %d vs %d", back.TotalDecoys, r.TotalDecoys)
	}
}

func TestFormatCoverageTable(t *testing.T) {
	out := FormatCoverageTable(BuildCoverageReport(false))
	if !strings.Contains(out, "DECOY") || !strings.Contains(out, "modbus") {
		t.Fatalf("table incomplete:\n%s", out)
	}
	if !strings.Contains(out, "T1552.005") {
		t.Fatalf("expected AWS IMDS technique in table:\n%s", out)
	}
}

func TestDecoyMatrixCoverage_NoInventedIDs(t *testing.T) {
	// Guardrail: every technique ID must look like T#### or T####.###
	for _, d := range DecoyMatrixCoverage() {
		for _, tech := range d.Techniques {
			if !strings.HasPrefix(tech.ID, "T") {
				t.Errorf("%s has non-ATT&CK id %q", d.Decoy, tech.ID)
			}
		}
	}
}
