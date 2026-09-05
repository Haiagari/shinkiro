package cluster

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestHub_IngestHandler(t *testing.T) {
	events := make(chan intel.Event, 10)
	hub := NewHub(events)

	ev := intel.Event{
		ID:          "ev-remote-01",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "redis",
		RemoteIP:    "198.51.100.33",
		LocalPort:   6379,
		Severity:    intel.SeverityHigh,
		ThreatScore: 75,
	}

	body, _ := json.Marshal(ev)
	req := httptest.NewRequest("POST", "/api/v1/cluster/ingest", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hub.IngestHandler(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", w.Code)
	}

	select {
	case received := <-events:
		if received.ID != "ev-remote-01" {
			t.Errorf("expected event ev-remote-01, got %s", received.ID)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for ingested cluster event")
	}
}
