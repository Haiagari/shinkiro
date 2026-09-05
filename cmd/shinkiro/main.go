package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/Haiagari/shinkiro/internal/adversary"
	"github.com/Haiagari/shinkiro/internal/canary"
	"github.com/Haiagari/shinkiro/internal/cluster"
	"github.com/Haiagari/shinkiro/internal/config"
	"github.com/Haiagari/shinkiro/internal/core"
	"github.com/Haiagari/shinkiro/internal/decoys/aws"
	"github.com/Haiagari/shinkiro/internal/decoys/dns"
	"github.com/Haiagari/shinkiro/internal/decoys/docker"
	"github.com/Haiagari/shinkiro/internal/decoys/elastic"
	decoyhttp "github.com/Haiagari/shinkiro/internal/decoys/http"
	"github.com/Haiagari/shinkiro/internal/decoys/k8s"
	"github.com/Haiagari/shinkiro/internal/decoys/mongo"
	"github.com/Haiagari/shinkiro/internal/decoys/postgres"
	"github.com/Haiagari/shinkiro/internal/decoys/redis"
	"github.com/Haiagari/shinkiro/internal/decoys/smtp"
	"github.com/Haiagari/shinkiro/internal/decoys/ssh"
	"github.com/Haiagari/shinkiro/internal/decoys/smb"
	"github.com/Haiagari/shinkiro/internal/decoys/telnet"
	"github.com/Haiagari/shinkiro/internal/decoys/mqtt"
	"github.com/Haiagari/shinkiro/internal/decoys/modbus"
	"github.com/Haiagari/shinkiro/internal/defense"
	"github.com/Haiagari/shinkiro/internal/ebpf"
	"github.com/Haiagari/shinkiro/internal/intel"
	"github.com/Haiagari/shinkiro/internal/intel/geoip"
	"github.com/Haiagari/shinkiro/internal/intel/ecs"
	"github.com/Haiagari/shinkiro/internal/intel/siem"
	"github.com/Haiagari/shinkiro/internal/intel/stix"
	"github.com/Haiagari/shinkiro/internal/metrics"
	"github.com/Haiagari/shinkiro/internal/soar"
	"github.com/Haiagari/shinkiro/internal/tui"
	"github.com/Haiagari/shinkiro/internal/webhook"
)

const banner = `
   _____ __    _       __   _             
  / ___// /_  (_)___  / /__(_)________  __
  \__ \/ __ \/ / __ \/ //_/ / ___/ __ \/ /
 ___/ / / / / / / / / ,< / / /  / /_/ / / 
/____/_/ /_/_/_/ /_/_/|_/_/_/   \____/_/  
   蜃気楼 — Ephemeral Deception & Attacker Intelligence Mesh
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "up":
		runUp(false)
	case "tui":
		runUp(true)
	case "canary":
		runCanary(os.Args[2:])
	case "export":
		runExport(os.Args[2:])
	case "stix":
		runSTIX(os.Args[2:])
	case "ecs":
		runECS(os.Args[2:])
	case "cef":
		runCEF(os.Args[2:])
	case "syslog":
		runSyslog(os.Args[2:])
	case "cluster":
		runCluster(os.Args[2:])
	case "ebpf", "kernel":
		runEBPF(os.Args[2:])
	case "simulate", "attack":
		runSimulate(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("Shinkiro v0.4.0 — High-Interaction Deception Engine (Haiagari Security)")
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Print(banner)
	fmt.Print(`
USAGE:
  shinkiro up                     Start background decoy listeners & Prometheus metrics
  shinkiro tui                    Launch live interactive terminal telemetry dashboard
  shinkiro canary generate        Generate synthetic HMAC-signed AWS/DB honeytokens
  shinkiro export blocklist       Export malicious IPs to firewall format
  shinkiro stix                   Export threat intelligence in STIX 2.1 JSON bundle
  shinkiro ecs                    Export telemetry in Elastic Common Schema (ECS v8.x) format
  shinkiro cef                    Export telemetry in ArcSight Common Event Format (CEF)
  shinkiro syslog                 Export telemetry as RFC5424 Syslog stream
  shinkiro cluster hub            Start distributed threat intelligence sync hub
  shinkiro kernel [rules]         Generate kernel-level XDP/eBPF / nftables drop rules
  shinkiro simulate               Execute red-team adversarial probe suite against decoys
  shinkiro version                Display engine version

OPTIONS:
  --config <path>                 Path to configuration YAML (default: config.yaml)
  --format <iptables|nftables|cidr> Firewall syntax (default: iptables)
  --threshold <score>             Minimum threat score to trigger mitigation (default: 80)
`)
}

func runCanary(args []string) {
	fs := flag.NewFlagSet("canary", flag.ExitOnError)
	label := fs.String("label", "canary-prod-seed", "Attribution tag for the canary token")
	_ = fs.Parse(args)

	token := canary.GenerateAWSKey(*label)
	data, _ := json.MarshalIndent(token, "", "  ")
	fmt.Println(string(data))
}

func runUp(interactiveUI bool) {
	if !interactiveUI {
		fmt.Print(banner)
	}

	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Printf("❌ Configuration error: %v\n", err)
		os.Exit(1)
	}

	intelEngine, err := intel.NewEngine(cfg.AuditLogPath)
	if err != nil {
		fmt.Printf("❌ Failed to initialize intel engine: %v\n", err)
		os.Exit(1)
	}

	dispatcher := webhook.NewDispatcher(os.Getenv("SHINKIRO_WEBHOOK_URL"))
	geoResolver := geoip.NewResolver()
	events := make(chan intel.Event, 200)
	tuiEvents := make(chan intel.Event, 200)
	mux := core.NewMultiplexer(cfg, events)

	// Register 11 High-Interaction Decoy Services
	mux.RegisterDecoy(ssh.New())
	mux.RegisterDecoy(redis.New())
	mux.RegisterDecoy(docker.New())
	mux.RegisterDecoy(decoyhttp.New())
	mux.RegisterDecoy(postgres.New())
	mux.RegisterDecoy(k8s.New())
	mux.RegisterDecoy(aws.New())
	mux.RegisterDecoy(mongo.New())
	mux.RegisterDecoy(elastic.New())
	mux.RegisterDecoy(smtp.New())
	mux.RegisterDecoy(dns.New())
	mux.RegisterDecoy(smb.New())
	mux.RegisterDecoy(telnet.New())
	mux.RegisterDecoy(mqtt.New())
	mux.RegisterDecoy(modbus.New())

	soarEngine := soar.NewEngine()
	_ = soarEngine.LoadYAML("playbooks.yaml")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Consumer loop for threat intelligence, webhooks, metrics, and SOAR playbooks
	go func() {
		for ev := range events {
			metrics.IncConnections()
			// Execute SOAR playbooks
			soarActions := soarEngine.Process(ev)
			for _, act := range soarActions {
				fmt.Printf("🛡️  [SOAR] %s\n", act)
			}
			if ev.Severity == intel.SeverityCritical {
				metrics.IncCritical()
				_ = dispatcher.SendAlert(ev)
			}
			if ev.ThreatScore >= 80 {
				metrics.IncBlocked()
			}

			switch ev.DecoyName {
			case "ssh":
				metrics.IncSSH()
			case "redis":
				metrics.IncRedis()
			case "docker":
				metrics.IncDocker()
			case "postgres", "mongo":
				metrics.IncDatabase()
			}

			// Enrich with GeoIP & ASN
			geo := geoResolver.Lookup(ev.RemoteIP)
			if ev.Metadata == nil {
				ev.Metadata = make(map[string]string)
			}
			ev.Metadata["geo_country"] = geo.Country
			ev.Metadata["geo_city"] = geo.City
			ev.Metadata["geo_asn"] = geo.ASN
			ev.Metadata["geo_org"] = geo.Org

			_ = intelEngine.Record(ev)
			if interactiveUI {
				select {
				case tuiEvents <- ev:
				default:
				}
			} else {
				fmt.Printf("🚨 [%s] %-8s probe from %s [%s/%s] on port %d -> %s (Threat: %d)\n",
					ev.Severity, ev.DecoyName, ev.RemoteIP, geo.Country, geo.ASN, ev.LocalPort, ev.Action, ev.ThreatScore)
			}
		}
	}()

	// Start Prometheus / OpenMetrics endpoint
	if cfg.MetricsPort > 0 {
		http.HandleFunc("/metrics", metrics.Handler)
		metricsServer := &http.Server{Addr: fmt.Sprintf(":%d", cfg.MetricsPort)}
		go func() {
			_ = metricsServer.ListenAndServe()
		}()
	}

	if err := mux.Start(ctx); err != nil {
		fmt.Printf("❌ Failed to bind honeypot listeners: %v\n", err)
		os.Exit(1)
	}

	activePorts := make([]int, 0)
	for _, svc := range cfg.Services {
		if svc.Enabled {
			activePorts = append(activePorts, svc.Port)
		}
	}

	if interactiveUI {
		p := tea.NewProgram(tui.NewModel(tuiEvents, activePorts), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Printf("TUI error: %v\n", err)
		}
		mux.Stop()
		return
	}

	fmt.Println("⚡ Decoy mesh is active and listening:")
	for name, svc := range cfg.Services {
		if svc.Enabled {
			fmt.Printf("   • %-10s -> tcp/%d\n", name, svc.Port)
		}
	}
	if cfg.MetricsPort > 0 {
		fmt.Printf("📊 Prometheus metrics available at: http://0.0.0.0:%d/metrics\n", cfg.MetricsPort)
	}
	fmt.Println("Audit logs streaming to:", cfg.AuditLogPath)
	fmt.Println("Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n🛑 Gracefully stopping Shinkiro honeynet...")
	mux.Stop()
	cancel()
	fmt.Println("✅ Shutdown complete.")
}

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

func runCluster(args []string) {
	fs := flag.NewFlagSet("cluster", flag.ExitOnError)
	port := fs.Int("port", 9090, "Cluster sync hub HTTP port")
	_ = fs.Parse(args)

	events := make(chan intel.Event, 500)
	hub := cluster.NewHub(events)

	fmt.Printf("🌐 Starting Shinkiro Distributed Threat Hub on :%d...\n", *port)
	ctx := context.Background()
	if err := hub.StartHTTP(ctx, *port); err != nil {
		fmt.Printf("❌ Cluster Hub exited: %v\n", err)
	}
}

func runEBPF(args []string) {
	fs := flag.NewFlagSet("kernel", flag.ExitOnError)
	driverStr := fs.String("driver", "nftables", "Driver: nftables, ebpf, iptables")
	iface := fs.String("iface", "eth0", "Network interface for XDP/ingress filter")
	_ = fs.Parse(args)

	intelEngine, err := intel.NewEngine("data/events.jsonl")
	if err != nil {
		fmt.Printf("❌ Failed to read intel engine: %v\n", err)
		os.Exit(1)
	}

	maliciousIPs := intelEngine.MaliciousIPs(80)
	fm := ebpf.NewFilterManager(ebpf.Driver(*driverStr), *iface)
	for _, ip := range maliciousIPs {
		_ = fm.BlockIP(ip)
	}

	fmt.Print(fm.RenderScript())
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


func runSimulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "Target host running Shinkiro mesh")
	_ = fs.Parse(args)

	fmt.Println("⚔️  Launching synthetic adversary attack suite against " + *host)
	sim := adversary.NewSimulator(*host, 2*time.Second)
	scenarios := adversary.DefaultScenarios()

	for i, sc := range scenarios {
		fmt.Printf("[%d/%d] 🎯 Testing %s (%s/%d)... ", i+1, len(scenarios), sc.Name, sc.Protocol, sc.Port)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := sim.RunScenario(ctx, sc)
		cancel()
		if err != nil {
			fmt.Println("⚠️  Failed/Closed: " + err.Error())
		} else {
			fmt.Println("✅ Intercepted & Baited!")
		}
	}
	fmt.Println("✨ Adversarial simulation complete.")
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
