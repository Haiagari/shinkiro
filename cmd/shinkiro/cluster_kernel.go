package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Haiagari/shinkiro/internal/cluster"
	"github.com/Haiagari/shinkiro/internal/ebpf"
	"github.com/Haiagari/shinkiro/internal/intel"
)

func runCluster(args []string) {
	fs := flag.NewFlagSet("cluster", flag.ExitOnError)
	port := fs.Int("port", 9090, "Cluster sync hub HTTP port")
	_ = fs.Parse(args)

	events := make(chan intel.Event, 500)
	hub := cluster.NewHub(events)

	fmt.Printf("Starting Shinkiro Distributed Threat Hub on :%d...\n", *port)
	ctx := context.Background()
	if err := hub.StartHTTP(ctx, *port); err != nil {
		fmt.Printf("Cluster Hub exited: %v\n", err)
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
