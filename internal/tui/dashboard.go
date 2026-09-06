package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/Haiagari/shinkiro/internal/canary"
	"github.com/Haiagari/shinkiro/internal/intel"
	"github.com/Haiagari/shinkiro/internal/pcap"
	"github.com/Haiagari/shinkiro/internal/soar"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Bold(true)

	criticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0055")).
			Bold(true)

	highStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF8800")).
			Bold(true)

	mediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFCC00"))

	lowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00CCFF"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1).
			Width(96)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A3E635"))

	selectStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#333355")).
			Foreground(lipgloss.Color("#FFFFFF"))

	helpBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#22D3EE")).
			Padding(1).
			Width(96)
)

// Config wires real operator backends into the TUI (no placeholders).
type Config struct {
	EventChan    <-chan intel.Event
	Ports        []int
	Engine       *intel.Engine
	Blocker      *soar.BlockApplier
	PCAP         *pcap.OnDemandCapture
	ApplyLive    bool
	SimulateHost string
	MinScore     int // high-score refresh floor (default 50)
	CanaryLabel  string
	// Optional injectables for unit tests (nil → real packages).
	SimulateFn func(host string) (string, error)
	CanaryFn   func(label string) canary.Token
}

// Model is the Bubble Tea dashboard with operator actions.
type Model struct {
	cfg         Config
	events      []intel.Event
	campaigns   []*intel.Campaign
	cursor      int
	focus       FocusPane
	help        bool
	status      string
	activePorts []int
	totalProbes int
	criticals   int
}

// NewModel builds the operator TUI. Prefer Config with Blocker/PCAP/Engine wired from up/tui.
func NewModel(cfg Config) Model {
	if cfg.SimulateHost == "" {
		cfg.SimulateHost = "127.0.0.1"
	}
	if cfg.MinScore <= 0 {
		cfg.MinScore = 50
	}
	m := Model{
		cfg:         cfg,
		events:      make([]intel.Event, 0),
		campaigns:   make([]*intel.Campaign, 0),
		activePorts: cfg.Ports,
	}
	if cfg.Engine != nil {
		_ = m.RefreshFromStore()
		m.status = ""
	}
	return m
}

type eventMsg intel.Event

type statusMsg string

type simulateDoneMsg ActionResult

func (m Model) Init() tea.Cmd {
	if m.cfg.EventChan == nil {
		return nil
	}
	return m.waitForEvent()
}

func (m Model) waitForEvent() tea.Cmd {
	ch := m.cfg.EventChan
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return eventMsg(ev)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKey(msg)
	case eventMsg:
		ev := intel.Event(msg)
		m.totalProbes++
		if ev.Severity == intel.SeverityCritical {
			m.criticals++
		}
		m.events = append([]intel.Event{ev}, m.events...)
		if len(m.events) > 15 {
			m.events = m.events[:15]
		}
		if m.focus == FocusEvents {
			m.cursor++
			m.clampCursor()
		}
		if m.cfg.Engine != nil && m.cfg.Engine.Correlator != nil {
			m.campaigns = SortCampaignsByScore(m.cfg.Engine.Correlator.ActiveCampaigns())
			if len(m.campaigns) > 15 {
				m.campaigns = m.campaigns[:15]
			}
		}
		return m, m.waitForEvent()
	case simulateDoneMsg:
		m.status = msg.Status
		return m, nil
	case statusMsg:
		m.status = string(msg)
		return m, nil
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?", "h":
		m.help = !m.help
		return m, nil
	case "esc", "x":
		m.help = false
		m.status = ""
		return m, nil
	case "tab":
		if m.focus == FocusEvents {
			m.focus = FocusCampaigns
		} else {
			m.focus = FocusEvents
		}
		m.cursor = 0
		m.clampCursor()
		return m, nil
	case "up", "k":
		m.moveCursor(-1)
		return m, nil
	case "down", "j":
		m.moveCursor(1)
		return m, nil
	case "r":
		res := m.RefreshFromStore()
		m.status = res.Status
		return m, nil
	case "b":
		res := m.DispatchBlock()
		m.status = res.Status
		return m, nil
	case "p":
		res := m.DispatchPCAP()
		m.status = res.Status
		return m, nil
	case "c":
		res := m.DispatchCanary()
		m.status = res.Status
		return m, nil
	case "s":
		m.status = fmt.Sprintf("simulate: running scenarios vs %s…", m.cfg.SimulateHost)
		host := m.cfg.SimulateHost
		fn := m.cfg.SimulateFn
		return m, func() tea.Msg {
			return simulateDoneMsg(RunSimulateSync(host, fn))
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.help {
		return helpBoxStyle.Render(HelpText) + "\n" + m.statusLine()
	}

	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" 蜃気楼 SHINKIRO — Operator TUI (decoy telemetry + SOAR/PCAP actions) "))
	sb.WriteString("\n\n")

	blockMode := "dry-run"
	if m.cfg.ApplyLive {
		blockMode = "LIVE apply"
	}
	stats := fmt.Sprintf("⚡ Decoy listeners: %d ports  |  🚨 Probes: %d  |  🔥 Critical: %d  |  SOAR block_ip: %s",
		len(m.activePorts), m.totalProbes, m.criticals, blockMode)
	sb.WriteString(boxStyle.Render(stats))
	sb.WriteString("\n\n")

	eventsLabel := "EVENTS (live + high-score)"
	campLabel := "CAMPAIGNS (correlator)"
	if m.focus == FocusEvents {
		eventsLabel = "> " + eventsLabel
	} else {
		campLabel = "> " + campLabel
	}
	sb.WriteString(headerStyle.Render(eventsLabel + "   |   " + campLabel))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 96))
	sb.WriteString("\n")

	if m.focus == FocusCampaigns {
		sb.WriteString(m.renderCampaigns())
	} else {
		sb.WriteString(m.renderEvents())
	}

	sb.WriteString("\n")
	sb.WriteString(headerStyle.Render(KeyHintFooter))
	sb.WriteString("\n")
	sb.WriteString(m.statusLine())
	return sb.String()
}

func (m Model) statusLine() string {
	if m.status == "" {
		return statusStyle.Render("status: (idle — press ? for help)")
	}
	return statusStyle.Render("status: " + m.status)
}

func (m Model) renderEvents() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-2s %-8s %-10s %-16s %-6s %-5s %-10s %-28s\n",
		"", "TIME", "DECOY", "ATTACKER IP", "PORT", "SCR", "SEVERITY", "ACTION"))
	sb.WriteString(strings.Repeat("─", 96))
	sb.WriteString("\n")
	if len(m.events) == 0 {
		sb.WriteString("  (no events yet — waiting on decoy probes, or press r to refresh store)\n")
		return sb.String()
	}
	for i, ev := range m.events {
		sevFormatted := string(ev.Severity)
		switch ev.Severity {
		case intel.SeverityCritical:
			sevFormatted = criticalStyle.Render(string(ev.Severity))
		case intel.SeverityHigh:
			sevFormatted = highStyle.Render(string(ev.Severity))
		case intel.SeverityMedium:
			sevFormatted = mediumStyle.Render(string(ev.Severity))
		case intel.SeverityLow:
			sevFormatted = lowStyle.Render(string(ev.Severity))
		}
		timeStr := ev.Timestamp.Format("15:04:05")
		actionStr := ev.Action
		if len(actionStr) > 28 {
			actionStr = actionStr[:25] + "..."
		}
		marker := " "
		if i == m.cursor {
			marker = ">"
		}
		line := fmt.Sprintf("%-2s %-8s %-10s %-16s %-6d %-5d %-18s %-28s",
			marker, timeStr, ev.DecoyName, ev.RemoteIP, ev.LocalPort, ev.ThreatScore, sevFormatted, actionStr)
		if i == m.cursor {
			line = selectStyle.Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) renderCampaigns() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-2s %-16s %-5s %-6s %-8s %-40s\n",
		"", "ATTACKER IP", "EVTS", "MAXSCR", "DECOYS", "CAMPAIGN ID"))
	sb.WriteString(strings.Repeat("─", 96))
	sb.WriteString("\n")
	if len(m.campaigns) == 0 {
		sb.WriteString("  (no active campaigns in correlator — probes will populate this pane)\n")
		return sb.String()
	}
	for i, c := range m.campaigns {
		if c == nil {
			continue
		}
		marker := " "
		if i == m.cursor {
			marker = ">"
		}
		decoys := strings.Join(c.DecoysTargeted, ",")
		if len(decoys) > 8 {
			decoys = decoys[:5] + "..."
		}
		id := c.ID
		if len(id) > 40 {
			id = id[:37] + "..."
		}
		line := fmt.Sprintf("%-2s %-16s %-5d %-6d %-8s %-40s",
			marker, c.AttackerIP, c.TotalEvents, c.MaxThreatScore, decoys, id)
		if i == m.cursor {
			line = selectStyle.Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}
