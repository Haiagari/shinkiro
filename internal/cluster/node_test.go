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
	hub := NewHubWithConfig(events, HubConfig{}) // lab-only, no token

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

func TestRequireToken_RejectsMissingAndWrong_AcceptsCorrect(t *testing.T) {
	events := make(chan intel.Event, 4)
	hub := NewHubWithConfig(events, HubConfig{Token: "s3cret-cluster-token"})
	srv := hub.Handler()

	ev := intel.Event{
		ID:        "ev-auth-01",
		Timestamp: time.Now().UTC(),
		DecoyName: "ssh",
		RemoteIP:  "203.0.113.9",
	}
	body, _ := json.Marshal(ev)

	{
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/ingest", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("missing token: want 401, got %d body=%s", w.Code, w.Body.String())
		}
		var errBody map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("expected JSON error body: %v", err)
		}
		if errBody["error"] != "unauthorized" {
			t.Fatalf("expected error=unauthorized, got %q", errBody["error"])
		}
	}

	{
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/ingest", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong token: want 401, got %d", w.Code)
		}
	}

	{
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/ingest", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer s3cret-cluster-token")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("correct bearer: want 202, got %d body=%s", w.Code, w.Body.String())
		}
	}

	{
		ev2 := ev
		ev2.ID = "ev-auth-02"
		body2, _ := json.Marshal(ev2)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/ingest", bytes.NewReader(body2))
		req.Header.Set(HeaderClusterToken, "s3cret-cluster-token")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("correct header token: want 202, got %d", w.Code)
		}
	}
}

func TestRequireToken_JoinRejectsMissing_AcceptsCorrect(t *testing.T) {
	events := make(chan intel.Event, 1)
	hub := NewHubWithConfig(events, HubConfig{Token: "join-token"})
	srv := hub.Handler()

	payload := []byte(`{"id":"edge-1","address":"10.0.0.5:2222"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("join missing token: want 401, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer join-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("join with token: want 200, got %d body=%s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("nodes without token: want 401, got %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
	req.Header.Set("Authorization", "Bearer join-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("nodes with token: want 200, got %d", w.Code)
	}
	var nodes map[string]Node
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("nodes json: %v", err)
	}
	if nodes["edge-1"].Address != "10.0.0.5:2222" {
		t.Fatalf("expected edge-1 registered, got %#v", nodes)
	}
}

func TestHub_LabModeAllowsUnauthenticated(t *testing.T) {
	events := make(chan intel.Event, 2)
	hub := NewHubWithConfig(events, HubConfig{})
	srv := hub.Handler()

	payload := []byte(`{"id":"lab-node","address":"127.0.0.1:9091"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("lab join without token: want 200, got %d", w.Code)
	}
}

func TestHealthAndReadyUnauthenticated(t *testing.T) {
	events := make(chan intel.Event, 1)
	hub := NewHubWithConfig(events, HubConfig{Token: "locked"})
	srv := hub.Handler()

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", path, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var ready map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if ready["auth_mode"] != "token" {
		t.Fatalf("expected auth_mode=token, got %#v", ready["auth_mode"])
	}
	if ready["model"] != "hub-and-spoke-http" {
		t.Fatalf("expected model=hub-and-spoke-http, got %#v", ready["model"])
	}
}
