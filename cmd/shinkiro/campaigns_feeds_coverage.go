package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/intel"
)

func runCampaigns(args []string) {
	fs := flag.NewFlagSet("campaigns", flag.ExitOnError)
	format := fs.String("format", "table", "Output format: table | json")
	eventsPath := fs.String("events", "", "Path to events JSONL (default: config audit_log_path or data/events.jsonl)")
	window := fs.Duration("window", 2*time.Hour, "Session window for correlator v2 regrouping")
	_ = fs.Parse(args)

	path := *eventsPath
	if path == "" {
		if cfg, err := config.LoadConfig("config.yaml"); err == nil && cfg.AuditLogPath != "" {
			path = cfg.AuditLogPath
		} else {
			path = "data/events.jsonl"
		}
	}

	engine, err := intel.NewEngine(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "campaigns: failed to open intel store: %v\n", err)
		os.Exit(1)
	}

	// Rebuild correlator v2 from persisted events so CLI works without a live mesh.
	corr := intel.NewCorrelator(*window)
	events := engine.RecentEvents(0)
	for _, ev := range events {
		if ev.Mitre == nil {
			m := intel.MapToMitre(ev.DecoyName, ev.Action, ev.Command)
			ev.Mitre = &m
		}
		corr.Ingest(ev)
	}
	camps := corr.ActiveCampaignsSorted()

	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(camps); err != nil {
			fmt.Fprintf(os.Stderr, "campaigns: encode: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Print(intel.FormatCampaignsTable(camps))
		fmt.Printf("# Rebuilt %d campaign(s) from %d event(s) in %s (window=%s)\n",
			len(camps), len(events), path, window.String())
	}
}

func runThreatFox(args []string) {
	fs := flag.NewFlagSet("threatfox", flag.ExitOnError)
	search := fs.String("search", "", "IOC search term (IP, domain, hash, ...)")
	days := fs.Int("days", 0, "If >0, fetch recent IOCs for N days (1-7) instead of search")
	format := fs.String("format", "table", "Output format: table | json")
	_ = fs.Parse(args)

	client := intel.NewThreatFoxClient("", nil)
	var (
		iocs []intel.ThreatFoxIOC
		err  error
	)
	switch {
	case *days > 0:
		iocs, err = client.RecentIOCs(*days)
	case *search != "":
		iocs, err = client.SearchIOC(*search)
	default:
		fmt.Fprintln(os.Stderr, "threatfox: require --search <ioc> or --days <1-7>")
		fmt.Fprintln(os.Stderr, "Env: THREATFOX_API_KEY (Auth-Key from https://auth.abuse.ch/)")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "threatfox: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(iocs)
	default:
		if len(iocs) == 0 {
			fmt.Println("(no ThreatFox results)")
			return
		}
		fmt.Printf("%-28s %-12s %-8s %-20s %s\n", "IOC", "TYPE", "CONF", "MALWARE", "TAGS")
		fmt.Println(strings.Repeat("-", 90))
		for _, ioc := range iocs {
			tags := strings.Join(ioc.Tags, ",")
			fmt.Printf("%-28s %-12s %-8d %-20s %s\n",
				truncateCLI(ioc.IOC, 28), ioc.IOCType, ioc.Confidence,
				truncateCLI(ioc.MalwarePrintable, 20), truncateCLI(tags, 24))
		}
	}
}

func runAbuseIPDB(args []string) {
	fs := flag.NewFlagSet("abuseipdb", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address to check")
	maxAge := fs.Int("max-age", 90, "Max age in days for reports")
	format := fs.String("format", "table", "Output format: table | json")
	_ = fs.Parse(args)

	if strings.TrimSpace(*ip) == "" {
		fmt.Fprintln(os.Stderr, "abuseipdb: require --ip <address>")
		fmt.Fprintln(os.Stderr, "Env: ABUSEIPDB_API_KEY (https://www.abuseipdb.com/account/api)")
		os.Exit(1)
	}

	client := intel.NewAbuseIPDBClient("", nil)
	data, err := client.CheckIP(*ip, *maxAge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "abuseipdb: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(data)
	default:
		fmt.Printf("IP:                 %s\n", data.IPAddress)
		fmt.Printf("Abuse confidence:   %d\n", data.AbuseConfidenceScore)
		fmt.Printf("Total reports:      %d (distinct users: %d)\n", data.TotalReports, data.NumDistinctUsers)
		fmt.Printf("Country:            %s\n", data.CountryCode)
		fmt.Printf("ISP / usage:        %s / %s\n", data.ISP, data.UsageType)
		fmt.Printf("Domain:             %s\n", data.Domain)
		fmt.Printf("Whitelisted:        %v\n", data.IsWhitelisted)
		fmt.Printf("Last reported:      %s\n", data.LastReportedAt)
	}
}

func runCoverage(args []string) {
	fs := flag.NewFlagSet("coverage", flag.ExitOnError)
	format := fs.String("format", "table", "Output format: table | json")
	runtimeMapper := fs.Bool("runtime-mapper", false, "Also include techniques from MapToMitre heuristics")
	_ = fs.Parse(args)

	report := intel.BuildCoverageReport(*runtimeMapper)
	switch strings.ToLower(*format) {
	case "json":
		raw, err := intel.CoverageReportJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "coverage: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	default:
		fmt.Print(intel.FormatCoverageTable(report))
	}
}

func truncateCLI(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
