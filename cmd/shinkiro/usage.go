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
  shinkiro up [--apply]           Start decoy listeners; SOAR block_ip dry-run unless --apply
  shinkiro tui [--apply]          Live TUI dashboard (same pipeline / SOAR flags)
  shinkiro canary generate        Generate synthetic HMAC-signed AWS/DB honeytokens
  shinkiro campaigns              List correlator v2 campaigns (rebuild from events JSONL)
  shinkiro threatfox              Query ThreatFox IOCs (--search or --days; needs THREATFOX_API_KEY)
  shinkiro abuseipdb              Check IP reputation (--ip; needs ABUSEIPDB_API_KEY)
  shinkiro coverage               ATT&CK coverage report from decoy-matrix + optional MapToMitre
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
  --apply                         Live-execute SOAR block_ip firewall commands (default: dry-run)
  --config <path>                 Path to configuration YAML (default: config.yaml)
  --format <iptables|nftables|cidr> Firewall syntax (default: iptables)
  --threshold <score>             Minimum threat score to trigger mitigation (default: 80)

ENV:
  SHINKIRO_SOAR_APPLY=1           Same as --apply (live firewall exec / webhook POST)
  SHINKIRO_SOAR_BLOCK_FORMAT      nftables (default) | iptables | cidr
  SHINKIRO_SOAR_BLOCK_WEBHOOK     Optional URL for block_ip JSON POST when applying
  SHINKIRO_PCAP_THRESHOLD         On-demand PCAP score gate (default: 80)
  SHINKIRO_PCAP_DIR               On-demand PCAP directory (default: data/pcap)
  SHINKIRO_WEBHOOK_URL            Slack/Discord alert webhook for critical events
  THREATFOX_API_KEY               ThreatFox Auth-Key (https://auth.abuse.ch/) for threatfox CLI
  ABUSEIPDB_API_KEY               AbuseIPDB API key for abuseipdb CLI
`)
}
