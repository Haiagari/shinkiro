package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Haiagari/shinkiro/internal/cluster"
	"github.com/Haiagari/shinkiro/internal/ebpf"
	"github.com/Haiagari/shinkiro/internal/intel"
)

func runCluster(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: shinkiro cluster hub [flags]")
		os.Exit(1)
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "hub":
		runClusterHub(rest)
	default:
		// Backward compatible: `shinkiro cluster --port 9090`
		if strings.HasPrefix(sub, "-") {
			runClusterHub(args)
			return
		}
		fmt.Fprintf(os.Stderr, "unknown cluster subcommand: %s\nusage: shinkiro cluster hub [flags]\n", sub)
		os.Exit(1)
	}
}

func runClusterHub(args []string) {
	fs := flag.NewFlagSet("cluster hub", flag.ExitOnError)
	port := fs.Int("port", 9090, "Hub-and-spoke HTTP listen port")
	token := fs.String("token", "", "Shared secret (overrides SHINKIRO_CLUSTER_TOKEN; empty = lab-only insecure)")
	tlsCert := fs.String("tls-cert", "", "Optional TLS certificate path (requires --tls-key)")
	tlsKey := fs.String("tls-key", "", "Optional TLS private key path (requires --tls-cert)")
	_ = fs.Parse(args)

	cfg := cluster.DefaultHubConfig()
	if strings.TrimSpace(*token) != "" {
		cfg.Token = strings.TrimSpace(*token)
	}
	cfg.TLSCertFile = strings.TrimSpace(*tlsCert)
	cfg.TLSKeyFile = strings.TrimSpace(*tlsKey)

	events := make(chan intel.Event, 500)
	hub := cluster.NewHubWithConfig(events, cfg)

	authMode := "insecure-lab (empty token)"
	if hub.TokenConfigured() {
		authMode = "token (SHINKIRO_CLUSTER_TOKEN / --token)"
	}
	tlsMode := "plain HTTP (terminate TLS at reverse proxy if needed)"
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		tlsMode = "HTTPS (" + cfg.TLSCertFile + ")"
	}

	fmt.Printf("Starting Shinkiro cluster hub (hub-and-spoke HTTP, not gossip/mesh) on :%d\n", *port)
	fmt.Printf("  auth: %s\n", authMode)
	fmt.Printf("  tls:  %s\n", tlsMode)
	fmt.Printf("  endpoints: /healthz /readyz /api/v1/cluster/{join,ingest,nodes}\n")

	ctx := context.Background()
	if err := hub.StartHTTP(ctx, *port); err != nil {
		fmt.Printf("Cluster Hub exited: %v\n", err)
		os.Exit(1)
	}
}

func runEBPF(args []string) {
	fs := flag.NewFlagSet("kernel", flag.ExitOnError)
	driverStr := fs.String("driver", "nftables", "Driver: nftables, ebpf, iptables")
	iface := fs.String("iface", "eth0", "Network interface for XDP/ingress filter")
	_ = fs.Parse(args)

	intelEngine, err := intel.NewEngine("data/events.jsonl")
	if err != nil {
		fmt.Printf("Failed to read intel engine: %v\n", err)
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
