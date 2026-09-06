package main

import (
	"fmt"
	"os"
)

// Set via -ldflags "-X main.version=... -X main.commit=... -X main.date=..."
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "up":
		runUp(false, os.Args[2:])
	case "tui":
		runUp(true, os.Args[2:])
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
		fmt.Printf("Shinkiro %s (commit=%s date=%s) — High-Interaction Deception Engine (Haiagari Security)\n", version, commit, date)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}
