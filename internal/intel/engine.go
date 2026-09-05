package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Engine struct {
	eventsPath string
	mu         sync.Mutex
	blocklist  map[string]int // IP -> cumulative threat score
}

func NewEngine(eventsPath string) (*Engine, error) {
	if eventsPath == "" {
		eventsPath = "data/events.jsonl"
	}

	dir := filepath.Dir(eventsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create intel events dir: %w", err)
	}

	return &Engine{
		eventsPath: eventsPath,
		blocklist:  make(map[string]int),
	}, nil
}

func (e *Engine) Record(ev Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Ensure MITRE mapping is populated
	if ev.Mitre == nil {
		m := MapToMitre(ev.DecoyName, ev.Action, ev.Command)
		ev.Mitre = &m
	}

	// Update cumulative score
	e.blocklist[ev.RemoteIP] += ev.ThreatScore

	// Append to JSONL
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(e.eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}

func (e *Engine) MaliciousIPs(threshold int) []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	var malicious []string
	for ip, score := range e.blocklist {
		if score >= threshold {
			malicious = append(malicious, ip)
		}
	}
	return malicious
}

func (e *Engine) RecentEvents(limit int) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := os.ReadFile(e.eventsPath)
	if err != nil {
		return nil
	}

	var events []Event
	lines := splitLines(string(data))
	for _, l := range lines {
		if l == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(l), &ev); err == nil {
			events = append(events, ev)
		}
	}

	if limit > 0 && len(events) > limit {
		return events[len(events)-limit:]
	}
	return events
}

func splitLines(s string) []string {
	var res []string
	var cur []rune
	for _, r := range s {
		if r == '\n' {
			res = append(res, string(cur))
			cur = nil
		} else {
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		res = append(res, string(cur))
	}
	return res
}
