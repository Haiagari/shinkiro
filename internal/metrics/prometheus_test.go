package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_Handler(t *testing.T) {
	IncConnections()
	IncBlocked()
	IncCritical()
	IncSSH()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	Handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "shinkiro_connections_total") {
		t.Errorf("expected shinkiro_connections_total metric, got: %s", body)
	}
	if !strings.Contains(body, "shinkiro_critical_threats_total") {
		t.Errorf("expected critical threats metric, got: %s", body)
	}
}
