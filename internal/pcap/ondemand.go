package pcap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

const DefaultThreshold = 80
const DefaultDir = "data/pcap"

// TriggerResult describes an on-demand capture attempt.
type TriggerResult struct {
	Triggered bool
	Path      string
	Score     int
	Threshold int
}

// OnDemandCapture opens a libpcap file when an event threat score crosses a threshold.
// Uses the existing Writer/OpenCapture implementation — not continuous tap mirroring.
type OnDemandCapture struct {
	mu        sync.Mutex
	threshold int
	dir       string
	opened    map[string]*CaptureFile // keyed by sanitized IP
	paths     map[string]string
}

// NewOnDemandCapture prepares a threshold-gated forensic capture hook.
func NewOnDemandCapture(threshold int, dir string) *OnDemandCapture {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if dir == "" {
		dir = DefaultDir
	}
	return &OnDemandCapture{
		threshold: threshold,
		dir:       dir,
		opened:    make(map[string]*CaptureFile),
		paths:     make(map[string]string),
	}
}

// ThresholdFromEnv reads SHINKIRO_PCAP_THRESHOLD (default 80).
func ThresholdFromEnv() int {
	v := strings.TrimSpace(os.Getenv("SHINKIRO_PCAP_THRESHOLD"))
	if v == "" {
		return DefaultThreshold
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return DefaultThreshold
	}
	return n
}

// DirFromEnv reads SHINKIRO_PCAP_DIR (default data/pcap).
func DirFromEnv() string {
	v := strings.TrimSpace(os.Getenv("SHINKIRO_PCAP_DIR"))
	if v == "" {
		return DefaultDir
	}
	return v
}

// Threshold returns the configured score gate.
func (o *OnDemandCapture) Threshold() int {
	return o.threshold
}

// MaybeCapture writes a forensic frame when ThreatScore >= threshold.
// Returns Triggered=false below threshold without opening files.
func (o *OnDemandCapture) MaybeCapture(ev intel.Event) (TriggerResult, error) {
	res := TriggerResult{Score: ev.ThreatScore, Threshold: o.threshold}
	if ev.ThreatScore < o.threshold {
		return res, nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if err := os.MkdirAll(o.dir, 0755); err != nil {
		return res, fmt.Errorf("pcap dir: %w", err)
	}

	key := sanitizeIP(ev.RemoteIP)
	if key == "" {
		key = "unknown"
	}
	path, ok := o.paths[key]
	if !ok {
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		path = filepath.Join(o.dir, fmt.Sprintf("highscore-%s-%d.pcap", key, ts.Unix()))
		cf, err := OpenCapture(path)
		if err != nil {
			return res, err
		}
		o.opened[key] = cf
		o.paths[key] = path
	}

	cf := o.opened[key]
	payload, err := json.Marshal(map[string]interface{}{
		"type":         "shinkiro-ondemand-pcap",
		"id":           ev.ID,
		"decoy":        ev.DecoyName,
		"remote_ip":    ev.RemoteIP,
		"threat_score": ev.ThreatScore,
		"action":       ev.Action,
		"severity":     ev.Severity,
		"command":      ev.Command,
		"timestamp":    ev.Timestamp.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return res, err
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if err := cf.Write(ts, payload); err != nil {
		return res, err
	}

	res.Triggered = true
	res.Path = path
	return res, nil
}

// Close releases open capture files.
func (o *OnDemandCapture) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	var first error
	for k, cf := range o.opened {
		if err := cf.Close(); err != nil && first == nil {
			first = err
		}
		delete(o.opened, k)
	}
	return first
}

func sanitizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	ip = strings.ReplaceAll(ip, ":", "_")
	ip = strings.ReplaceAll(ip, "/", "_")
	ip = strings.ReplaceAll(ip, "..", "_")
	return ip
}
