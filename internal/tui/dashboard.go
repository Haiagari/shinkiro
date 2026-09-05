package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/Haiagari/shinkiro/internal/intel"
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
			Width(90)
)

type Model struct {
	events      []intel.Event
	eventChan   <-chan intel.Event
	activePorts []int
	totalProbes int
	criticals   int
}

func NewModel(eventChan <-chan intel.Event, ports []int) Model {
	return Model{
		events:      make([]intel.Event, 0),
		eventChan:   eventChan,
		activePorts: ports,
	}
}

type eventMsg intel.Event

func (m Model) Init() tea.Cmd {
	return m.waitForEvent()
}

func (m Model) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		ev := <-m.eventChan
		return eventMsg(ev)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
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
		return m, m.waitForEvent()
	}
	return m, nil
}

func (m Model) View() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render(" 蜃気楼 SHINKIRO — Ephemeral Deception & Attacker Intelligence Mesh "))
	sb.WriteString("\n\n")

	// Status stats
	stats := fmt.Sprintf("⚡ Active Decoys: %d ports  |  🚨 Total Probes: %d  |  🔥 Critical Threats: %d",
		len(m.activePorts), m.totalProbes, m.criticals)
	sb.WriteString(boxStyle.Render(stats))
	sb.WriteString("\n\n")

	sb.WriteString(headerStyle.Render("LIVE ADVERSARY TELEMETRY FEED (Press 'q' to exit):"))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 90))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%-8s %-10s %-16s %-6s %-10s %-30s\n",
		"TIME", "DECOY", "ATTACKER IP", "PORT", "SEVERITY", "ACTION"))
	sb.WriteString(strings.Repeat("─", 90))
	sb.WriteString("\n")

	for _, ev := range m.events {
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
		if len(actionStr) > 30 {
			actionStr = actionStr[:27] + "..."
		}

		sb.WriteString(fmt.Sprintf("%-8s %-10s %-16s %-6d %-18s %-30s\n",
			timeStr, ev.DecoyName, ev.RemoteIP, ev.LocalPort, sevFormatted, actionStr))
	}

	return sb.String()
}
