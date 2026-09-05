package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// Dispatcher broadcasts critical adversary intrusions to Slack/Discord webhooks
type Dispatcher struct {
	webhookURL string
	client     *http.Client
}

func NewDispatcher(webhookURL string) *Dispatcher {
	return &Dispatcher{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// BuildSlackPayload formats a Slack Block Kit message with rich SecOps context
func BuildSlackPayload(ev intel.Event) map[string]interface{} {
	geoStr := "Unknown"
	if ev.Metadata != nil && (ev.Metadata["geo_country"] != "" || ev.Metadata["geo_asn"] != "") {
		geoStr = fmt.Sprintf("%s (%s)", ev.Metadata["geo_country"], ev.Metadata["geo_asn"])
	}

	headerText := fmt.Sprintf("🚨 SHINKIRO INTRUSION ALERT: %s", ev.DecoyName)
	summaryText := fmt.Sprintf("*Decoy:* `%s` (Port %d)\n*Severity:* `%s` | *Threat Score:* `%d/100`\n*Attacker IP:* `%s`\n*Origin:* `%s`\n*Action:* `%s`",
		ev.DecoyName, ev.LocalPort, ev.Severity, ev.ThreatScore, ev.RemoteIP, geoStr, ev.Action)

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": headerText,
			},
		},
		{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": summaryText,
			},
		},
	}

	if ev.Username != "" || ev.Password != "" {
		creds := fmt.Sprintf("*Captured Credentials:* `%s` / `%s`", ev.Username, ev.Password)
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": creds,
			},
		})
	}

	if ev.Command != "" {
		cmdText := fmt.Sprintf("*Injected Command / Exploit:* ```%s```", ev.Command)
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": cmdText,
			},
		})
	}

	return map[string]interface{}{
		"text":   headerText,
		"blocks": blocks,
	}
}

// BuildDiscordPayload formats a rich embed for Discord SecOps webhooks
func BuildDiscordPayload(ev intel.Event) map[string]interface{} {
	color := 15158332 // Red
	if ev.Severity == intel.SeverityHigh {
		color = 15105570 // Orange
	}

	fields := []map[string]interface{}{
		{"name": "Decoy Service", "value": fmt.Sprintf("%s (Port %d)", ev.DecoyName, ev.LocalPort), "inline": true},
		{"name": "Attacker IP", "value": ev.RemoteIP, "inline": true},
		{"name": "Threat Score", "value": fmt.Sprintf("%d/100 (%s)", ev.ThreatScore, ev.Severity), "inline": true},
		{"name": "Action / Vector", "value": ev.Action, "inline": false},
	}

	if ev.Username != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Captured Credentials", "value": fmt.Sprintf("`%s:%s`", ev.Username, ev.Password), "inline": true,
		})
	}

	if ev.Command != "" {
		fields = append(fields, map[string]interface{}{
			"name": "Command / Payload", "value": fmt.Sprintf("```%s```", ev.Command), "inline": false,
		})
	}

	embed := map[string]interface{}{
		"title":       fmt.Sprintf("🚨 Honeypot Triggered: %s", ev.DecoyName),
		"description": "An adversary has triggered an in-memory cyber deception trap.",
		"color":       color,
		"fields":      fields,
		"timestamp":   ev.Timestamp.UTC().Format(time.RFC3339),
	}

	return map[string]interface{}{
		"embeds": []interface{}{embed},
	}
}

// SendAlert posts a structured alert message to Slack or Discord
func (d *Dispatcher) SendAlert(ev intel.Event) error {
	if d.webhookURL == "" {
		return nil
	}

	var payload map[string]interface{}
	if strings.Contains(d.webhookURL, "discord.com") {
		payload = BuildDiscordPayload(ev)
	} else {
		payload = BuildSlackPayload(ev)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := d.client.Post(d.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
