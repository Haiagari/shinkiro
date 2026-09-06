package soar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Haiagari/shinkiro/internal/defense"
)

// ApplyMode controls whether block_ip mutates the host firewall or only emits commands.
type ApplyMode string

const (
	// ApplyDryRun (default) generates nftables/iptables text and optional webhook payloads
	// without executing firewall binaries. Honest: no kernel auto-block claim.
	ApplyDryRun ApplyMode = "dry-run"
	// ApplyLive runs generated firewall commands and/or POSTs a webhook when enabled.
	ApplyLive ApplyMode = "apply"
)

// BlockResult is the outcome of a single block_ip apply attempt.
type BlockResult struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Mode      ApplyMode `json:"mode"`
	Format    string    `json:"format"`
	Commands  string    `json:"commands"`
	Applied   bool      `json:"applied"`
	WebhookOK bool      `json:"webhook_ok,omitempty"`
	Message   string    `json:"message"`
}

// CommandRunner executes a privileged firewall command. Injectable for tests.
type CommandRunner func(name string, args ...string) error

// BlockApplier implements the real SOAR block_ip apply path with dry-run default.
type BlockApplier struct {
	mu         sync.Mutex
	mode       ApplyMode
	format     defense.Format
	webhookURL string
	runner     CommandRunner
	client     *http.Client
	logf       func(string)
	last       []BlockResult
}

// BlockApplierConfig configures dry-run vs live apply behaviour.
type BlockApplierConfig struct {
	Mode       ApplyMode
	Format     defense.Format
	WebhookURL string
	Runner     CommandRunner
	Logf       func(string)
	HTTPClient *http.Client
}

// NewBlockApplier builds a BlockApplier. Defaults: dry-run, nftables, os/exec runner.
func NewBlockApplier(cfg BlockApplierConfig) *BlockApplier {
	mode := cfg.Mode
	if mode == "" {
		mode = ApplyDryRun
	}
	format := cfg.Format
	if format == "" {
		format = defense.FormatNFTables
	}
	runner := cfg.Runner
	if runner == nil {
		runner = defaultRunner
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string) {}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &BlockApplier{
		mode:       mode,
		format:     format,
		webhookURL: cfg.WebhookURL,
		runner:     runner,
		client:     client,
		logf:       logf,
	}
}

// ModeFromEnv returns ApplyLive only when SHINKIRO_SOAR_APPLY=1; otherwise dry-run.
func ModeFromEnv() ApplyMode {
	if os.Getenv("SHINKIRO_SOAR_APPLY") == "1" {
		return ApplyLive
	}
	return ApplyDryRun
}

// FormatFromEnv reads SHINKIRO_SOAR_BLOCK_FORMAT (nftables|iptables); default nftables.
func FormatFromEnv() defense.Format {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHINKIRO_SOAR_BLOCK_FORMAT"))) {
	case "iptables":
		return defense.FormatIPTables
	case "cidr":
		return defense.FormatCIDR
	default:
		return defense.FormatNFTables
	}
}

// WebhookFromEnv reads SHINKIRO_SOAR_BLOCK_WEBHOOK for optional POST on block_ip.
func WebhookFromEnv() string {
	return strings.TrimSpace(os.Getenv("SHINKIRO_SOAR_BLOCK_WEBHOOK"))
}

// BlockIP generates firewall commands for ip and either dry-runs or applies them.
// Live apply never claims silent kernel auto-block: it executes explicit iptables/nft
// commands and/or a webhook POST when configured.
func (a *BlockApplier) BlockIP(ip, reason string) (BlockResult, error) {
	if ip == "" {
		return BlockResult{}, fmt.Errorf("block_ip: empty IP")
	}
	cmds := defense.GenerateRules([]string{ip}, a.format)
	res := BlockResult{
		IP:       ip,
		Reason:   reason,
		Mode:     a.mode,
		Format:   string(a.format),
		Commands: cmds,
	}

	if a.mode != ApplyLive {
		res.Applied = false
		res.Message = fmt.Sprintf("dry-run: would block %s via %s (set SHINKIRO_SOAR_APPLY=1 or pass --apply to execute)", ip, a.format)
		a.logf(fmt.Sprintf("[SOAR block_ip dry-run] %s\n%s", res.Message, cmds))
		if a.webhookURL != "" {
			a.logf(fmt.Sprintf("[SOAR block_ip dry-run] webhook POST skipped (target=%s)", a.webhookURL))
		}
		a.record(res)
		return res, nil
	}

	if err := a.execCommands(cmds); err != nil {
		res.Message = fmt.Sprintf("apply failed for %s: %v", ip, err)
		a.logf("[SOAR block_ip apply] " + res.Message)
		a.record(res)
		return res, err
	}
	res.Applied = true
	res.Message = fmt.Sprintf("applied %s block for %s", a.format, ip)
	a.logf("[SOAR block_ip apply] " + res.Message + "\n" + cmds)

	if a.webhookURL != "" {
		if err := a.postWebhook(res); err != nil {
			res.Message += fmt.Sprintf("; webhook error: %v", err)
			a.logf("[SOAR block_ip apply] webhook error: " + err.Error())
		} else {
			res.WebhookOK = true
		}
	}
	a.record(res)
	return res, nil
}

// Hook returns a soar.SetBlockHook-compatible function.
func (a *BlockApplier) Hook() func(ip, reason string) error {
	return func(ip, reason string) error {
		_, err := a.BlockIP(ip, reason)
		return err
	}
}

// LastResults returns a copy of recorded block attempts (tests / operators).
func (a *BlockApplier) LastResults() []BlockResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]BlockResult, len(a.last))
	copy(out, a.last)
	return out
}

func (a *BlockApplier) record(res BlockResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = append(a.last, res)
}

func (a *BlockApplier) execCommands(script string) error {
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch a.format {
		case defense.FormatIPTables:
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if err := a.runner(fields[0], fields[1:]...); err != nil {
				return fmt.Errorf("%s: %w", line, err)
			}
		case defense.FormatNFTables:
			if err := a.runner("nft", strings.Fields(line)...); err != nil {
				return fmt.Errorf("nft %s: %w", line, err)
			}
		default:
			a.logf("[SOAR block_ip apply] format " + string(a.format) + " has no local exec path; commands emitted only")
		}
	}
	return nil
}

func (a *BlockApplier) postWebhook(res BlockResult) error {
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	resp, err := a.client.Post(a.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func defaultRunner(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
