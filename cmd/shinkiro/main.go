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
		fmt.Printf("Shinkiro %s (commit=%s date=%s) — High-Interaction Deception Engine (Haiagari Security)\n", version, commit, date)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}
