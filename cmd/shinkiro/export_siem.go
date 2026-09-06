package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/defense"
	"github.com/Haiagari/shinkiro/internal/intel"
	"github.com/Haiagari/shinkiro/internal/intel/ecs"
	"github.com/Haiagari/shinkiro/internal/intel/siem"
	"github.com/Haiagari/shinkiro/internal/intel/stix"
)

func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	formatStr := fs.String("format", "iptables", "Firewall format: iptables, nftables, cidr")
	threshold := fs.Int("threshold", 80, "Minimum threat score to block")
	_ = fs.Parse(args)

	intelEngine, err := intel.NewEngine("data/events.jsonl")
	if err != nil {
		fmt.Printf("❌ Failed to read intel engine: %v\n", err)
		os.Exit(1)
	}

	maliciousIPs := intelEngine.MaliciousIPs(*threshold)
	if len(maliciousIPs) == 0 {
		fmt.Println("# No malicious IPs exceeding threat threshold yet.")
		return
	}

	rules := defense.GenerateRules(maliciousIPs, defense.Format(*formatStr))
	fmt.Print(rules)
}

func runSTIX(args []string) {
	data, err := os.ReadFile("data/events.jsonl")
	if err != nil {
		if os.IsNotExist(err) {
			emptyBundle, _ := stix.ConvertEventsToSTIX(nil)
			fmt.Println(string(emptyBundle))
			return
		}
		fmt.Printf("❌ Failed to read events log: %v\n", err)
		return
	}


	var events []intel.Event
	lines := splitLines(string(data))
	for _, l := range lines {
		if l == "" {
			continue
		}
		var ev intel.Event
		if err := json.Unmarshal([]byte(l), &ev); err == nil {
			events = append(events, ev)
		}
	}

	stixBundle, err := stix.ConvertEventsToSTIX(events)
	if err != nil {
		fmt.Printf("❌ Failed to generate STIX bundle: %v\n", err)
		return
	}

	fmt.Println(string(stixBundle))
}

func runECS(args []string) {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	engine, err := intel.NewEngine(cfg.AuditLogPath)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	events := engine.RecentEvents(500)
	data, err := ecs.ConvertBatchToECSJSON(events, cfg.NodeName)
	if err != nil {
		fmt.Println("Error encoding ECS: " + err.Error())
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func runCEF(args []string) {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	engine, err := intel.NewEngine(cfg.AuditLogPath)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	events := engine.RecentEvents(500)
	for _, ev := range events {
		fmt.Println(siem.FormatCEF(ev, cfg.NodeName))
	}
}

func runSyslog(args []string) {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	engine, err := intel.NewEngine(cfg.AuditLogPath)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		os.Exit(1)
	}

	events := engine.RecentEvents(500)
	for _, ev := range events {
		fmt.Println(siem.FormatSyslog(ev, cfg.NodeName))
	}
}
