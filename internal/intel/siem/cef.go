package siem

import (
	"fmt"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/intel"
)

// FormatCEF formats an Event into ArcSight Common Event Format (CEF)
func FormatCEF(ev intel.Event, deviceHost string) string {
	if deviceHost == "" {
		deviceHost = "shinkiro-sensor"
	}

	cefSeverity := 3
	switch ev.Severity {
	case intel.SeverityCritical:
		cefSeverity = 10
	case intel.SeverityHigh:
		cefSeverity = 8
	case intel.SeverityMedium:
		cefSeverity = 5
	case intel.SeverityLow:
		cefSeverity = 3
	default:
		cefSeverity = 1
	}

	mitreID := "T1595"
	mitreName := "Active Scanning"
	if ev.Mitre != nil {
		mitreID = ev.Mitre.TechniqueID
		mitreName = ev.Mitre.TechniqueName
	}

	exts := []string{
		fmt.Sprintf("src=%s", ev.RemoteIP),
		fmt.Sprintf("spt=%d", ev.RemotePort),
		fmt.Sprintf("dpt=%d", ev.LocalPort),
		fmt.Sprintf("app=%s", ev.DecoyName),
		fmt.Sprintf("act=%s", escapeCEFValue(ev.Action)),
		fmt.Sprintf("rt=%d", ev.Timestamp.UnixNano()/int64(time.Millisecond)),
		fmt.Sprintf("cs1=%s", mitreID),
		fmt.Sprintf("cs1Label=MitreTechniqueID"),
		fmt.Sprintf("cs2=%s", escapeCEFValue(mitreName)),
		fmt.Sprintf("cs2Label=MitreTechniqueName"),
		fmt.Sprintf("cn1=%d", ev.ThreatScore),
		fmt.Sprintf("cn1Label=ThreatScore"),
	}

	if ev.Username != "" {
		exts = append(exts, fmt.Sprintf("suser=%s", escapeCEFValue(ev.Username)))
	}
	if ev.Command != "" {
		exts = append(exts, fmt.Sprintf("msg=%s", escapeCEFValue(ev.Command)))
	}

	return fmt.Sprintf("CEF:0|Haiagari|Shinkiro|1.0.0|%s|%s|%d|%s",
		ev.DecoyName,
		escapeCEFValue(ev.Action),
		cefSeverity,
		strings.Join(exts, " "),
	)
}

// FormatSyslog formats an Event as standard RFC5424 Syslog with CEF payload
func FormatSyslog(ev intel.Event, hostname string) string {
	if hostname == "" {
		hostname = "shinkiro-mesh"
	}
	cef := FormatCEF(ev, hostname)
	timestamp := ev.Timestamp.UTC().Format(time.RFC3339)
	return fmt.Sprintf("<134>1 %s %s shinkiro - - - %s", timestamp, hostname, cef)
}

func escapeCEFValue(val string) string {
	r := strings.ReplaceAll(val, "\\", "\\\\")
	r = strings.ReplaceAll(r, "=", "\\=")
	r = strings.ReplaceAll(r, "|", "\\|")
	return r
}
