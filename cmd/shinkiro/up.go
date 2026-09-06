package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
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
	"github.com/Haiagari/shinkiro/internal/intel"
	"github.com/Haiagari/shinkiro/internal/intel/geoip"
	"github.com/Haiagari/shinkiro/internal/metrics"
	"github.com/Haiagari/shinkiro/internal/soar"
	"github.com/Haiagari/shinkiro/internal/tui"
	"github.com/Haiagari/shinkiro/internal/webhook"
)

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
