package intel

import "time"

// Severity levels for attacker events
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Event represents an immutable attacker telemetry interaction
type Event struct {
	ID            string            `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	DecoyName     string            `json:"decoy_name"`
	RemoteAddr    string            `json:"remote_addr"`
	RemoteIP      string            `json:"remote_ip"`
	RemotePort    int               `json:"remote_port"`
	LocalPort     int               `json:"local_port"`
	Severity      Severity          `json:"severity"`
	ThreatScore   int               `json:"threat_score"`
	Action        string            `json:"action"`
	Username      string            `json:"username,omitempty"`
	Password      string            `json:"password,omitempty"`
	Command       string            `json:"command,omitempty"`
	PayloadHashes []string          `json:"payload_hashes,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}
