# Threat Telemetry & Dynamic Defense Specification

## Purpose
Collect, enrich, and serialize attacker interactions into high-fidelity IoCs and export automated firewall blocklists.

## Requirements

### Requirement: INTEL-1 — Attacker Event Logging
Every session interaction across all decoys MUST produce structured JSONL events with tamper-evident metadata.

#### Scenario: Attacker session event generation
- GIVEN a completed decoy interaction
- WHEN the session terminates
- THEN an event containing `timestamp`, `remote_ip`, `protocol`, `credentials`, `commands`, and `payload_hashes` is appended to the event stream

### Requirement: INTEL-2 — Automated Firewall Export
The CLI MUST provide a command to transform detected malicious IPs into iptables/nftables/CIDR format.

#### Scenario: Exporting active blocklist
- GIVEN detected attacker IPs with severity >= HIGH
- WHEN `shinkiro export blocklist --format iptables` is executed
- THEN formatted `iptables -A INPUT -s <IP> -j DROP` commands are written to stdout
