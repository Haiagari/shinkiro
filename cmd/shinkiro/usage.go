package main

import "fmt"

const banner = `
   _____ __    _       __   _             
  / ___// /_  (_)___  / /__(_)________  __
  \__ \/ __ \/ / __ \/ //_/ / ___/ __ \/ /
 ___/ / / / / / / / / ,< / / /  / /_/ / / 
/____/_/ /_/_/_/ /_/_/|_/_/_/   \____/_/  
   蜃気楼 — Ephemeral Deception & Attacker Intelligence Mesh
`

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
