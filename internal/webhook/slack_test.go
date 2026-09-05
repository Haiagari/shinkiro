package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

func TestDispatcher_SendAlert_SlackAndDiscord(t *testing.T) {
	var receivedBody map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ev := intel.Event{
		ID:          "alert-test",
		Timestamp:   time.Now().UTC(),
		DecoyName:   "redis",
		RemoteIP:    "10.0.0.99",
		LocalPort:   6379,
		Severity:    intel.SeverityCritical,
		ThreatScore: 90,
		Action:      "REDIS_EVAL_LUA_EXPLOIT",
		Command:     "os.execute('whoami')",
		Metadata: map[string]string{
			"geo_country": "Germany",
			"geo_asn":     "AS24940",
		},
	}

	// 1. Test Slack Payload
	dispatcherSlack := NewDispatcher(ts.URL)
	if err := dispatcherSlack.SendAlert(ev); err != nil {
		t.Fatalf("failed to send Slack alert: %v", err)
	}
	if _, ok := receivedBody["blocks"]; !ok {
		t.Fatal("expected Slack blocks in payload")
	}

	// 2. Test Discord Payload
	slackPayload := BuildSlackPayload(ev)
	if len(slackPayload["blocks"].([]map[string]interface{})) < 2 {
		t.Fatal("expected at least 2 blocks")
	}

	discordPayload := BuildDiscordPayload(ev)
	if len(discordPayload["embeds"].([]interface{})) == 0 {
		t.Fatal("expected discord embeds")
	}
}
