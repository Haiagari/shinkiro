package soar

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
	"gopkg.in/yaml.v3"
)

// Condition defines triggering criteria for a playbook rule
type Condition struct {
	Decoy        string `yaml:"decoy"`
	MinScore     int    `yaml:"min_score"`
	MinSeverity  string `yaml:"min_severity"`
	ActionMatch  string `yaml:"action_match"`
	Threshold    int    `yaml:"threshold"` // Number of events within window
	WindowSec    int    `yaml:"window_sec"`
}

// Action defines automated defensive responses
type Action struct {
	Type     string            `yaml:"type"` // "block_ip", "webhook", "tag"
	Target   string            `yaml:"target"`
	Params   map[string]string `yaml:"params"`
}

// Rule is an individual automation unit
type Rule struct {
	Name       string    `yaml:"name"`
	Enabled    bool      `yaml:"enabled"`
	If         Condition `yaml:"if"`
	Then       []Action  `yaml:"then"`
}

// PlaybookConfig holds the loaded SOAR rules
type PlaybookConfig struct {
	Rules []Rule `yaml:"rules"`
}

// Engine evaluates events against playbooks and executes defense actions
type Engine struct {
	rules      []Rule
	mu         sync.Mutex
	history    map[string][]time.Time // "ruleName:ip" -> timestamps
	blockedIPs map[string]bool
	blockHook  func(ip, reason string) error
	alertHook  func(msg string) error
}

// NewEngine creates a new SOAR playbook engine
func NewEngine() *Engine {
	return &Engine{
		rules:      make([]Rule, 0),
		history:    make(map[string][]time.Time),
		blockedIPs: make(map[string]bool),
	}
}

func (e *Engine) SetBlockHook(hook func(ip, reason string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockHook = hook
}

func (e *Engine) SetAlertHook(hook func(msg string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alertHook = hook
}

func (e *Engine) LoadYAML(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg PlaybookConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = cfg.Rules
	return nil
}

func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// Process evaluates an event against all active rules and triggers actions
func (e *Engine) Process(ev intel.Event) []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	var executedActions []string
	now := time.Now()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if !e.matchesCondition(rule.If, ev) {
			continue
		}

		// Check rate window if threshold > 1
		if rule.If.Threshold > 1 && rule.If.WindowSec > 0 {
			key := fmt.Sprintf("%s:%s", rule.Name, ev.RemoteIP)
			window := time.Duration(rule.If.WindowSec) * time.Second
			cutoff := now.Add(-window)

			var recent []time.Time
			for _, t := range e.history[key] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			recent = append(recent, now)
			e.history[key] = recent

			if len(recent) < rule.If.Threshold {
				continue
			}
		}

		// Trigger actions
		for _, act := range rule.Then {
			res := e.executeAction(act, ev, rule.Name)
			if res != "" {
				executedActions = append(executedActions, res)
			}
		}
	}

	return executedActions
}

func (e *Engine) matchesCondition(c Condition, ev intel.Event) bool {
	if c.Decoy != "" && c.Decoy != "*" && c.Decoy != ev.DecoyName {
		return false
	}
	if c.MinScore > 0 && ev.ThreatScore < c.MinScore {
		return false
	}
	if c.ActionMatch != "" && !strings.Contains(strings.ToUpper(ev.Action), strings.ToUpper(c.ActionMatch)) {
		return false
	}
	return true
}

func (e *Engine) executeAction(act Action, ev intel.Event, ruleName string) string {
	switch act.Type {
	case "block_ip":
		e.blockedIPs[ev.RemoteIP] = true
		if e.blockHook != nil {
			_ = e.blockHook(ev.RemoteIP, fmt.Sprintf("Triggered by SOAR rule %q", ruleName))
		}
		return fmt.Sprintf("BLOCK_IP %s (%s)", ev.RemoteIP, ruleName)
	case "alert", "notify":
		msg := fmt.Sprintf("[SOAR] Rule %s triggered for %s (Decoy: %s, Score: %d)", ruleName, ev.RemoteIP, ev.DecoyName, ev.ThreatScore)
		if e.alertHook != nil {
			_ = e.alertHook(msg)
		}
		return fmt.Sprintf("ALERT %s", msg)
	case "tag":
		return fmt.Sprintf("TAG %s -> %s", ev.RemoteIP, act.Target)
	default:
		return ""
	}
}

func (e *Engine) BlockedIPs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ips []string
	for ip := range e.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}
