package pcap

import (
	"os"
	"path/filepath"
	testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestOnDemand_BelowThresholdNoFile(t *testing.T) {
	dir := t.TempDir()
	o := NewOnDemandCapture(80, dir)
	defer o.Close()

	res, err := o.MaybeCapture(intel.Event{
		RemoteIP:    "192.0.2.1",
		ThreatScore: 40,
		Timestamp:   time.Now().UTC(),
		DecoyName:   "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Triggered {
		t.Fatal("must not trigger below threshold")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("expected no files, found %d", len(entries))
	}
}

func TestOnDemand_ThresholdTriggersCapture(t *testing.T) {
	dir := t.TempDir()
	o := NewOnDemandCapture(80, dir)
	defer o.Close()

	res, err := o.MaybeCapture(intel.Event{
		ID:          "e-high",
		RemoteIP:    "198.51.100.20",
		ThreatScore: 95,
		Timestamp:   time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		DecoyName:   "redis",
		Action:      "CONFIG",
		Severity:    intel.SeverityCritical,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Triggered {
		t.Fatal("expected trigger at score 95")
	}
	if res.Path == "" {
		t.Fatal("expected pcap path")
	}
	st, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("pcap missing: %v", err)
	}
	if st.Size() == 0 {
		t.Fatal("pcap file empty")
	}
	// Global header is 24 bytes; packet header + payload should grow beyond that.
	if st.Size() <= 24 {
		t.Fatalf("pcap too small (%d); expected packet frame", st.Size())
	}
}

func TestOnDemand_ExactThresholdTriggers(t *testing.T) {
	dir := t.TempDir()
	o := NewOnDemandCapture(80, dir)
	defer o.Close()

	res, err := o.MaybeCapture(intel.Event{
		RemoteIP:    "203.0.113.1",
		ThreatScore: 80,
		Timestamp:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Triggered {
		t.Fatal("score == threshold must trigger")
	}
	if filepath.Dir(res.Path) != dir {
		t.Fatalf("path dir=%s want %s", filepath.Dir(res.Path), dir)
	}
}
