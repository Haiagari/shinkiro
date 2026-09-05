# Changelog

All notable changes to **Shinkiro** are documented in this file following [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [v1.0.0] - 2026-09-05

### Added
- **Modbus/TCP Industrial Decoy (`:502`)**: ICS/SCADA PLC emulator supporting MBAP framing, holding registers, coils, and direct MITRE for ICS `T0855` mapping.
- **SOAR-Lite Playbook Automation Engine**: Declarative YAML playbooks (`playbooks.yaml`) for rule-based automated IP containment and alerting.
- **Enterprise SIEM Exporters**: Native ArcSight CEF, RFC5424 Syslog, Elastic Common Schema (ECS v8.x), STIX 2.1, and ThreatFox/AbuseIPDB feed generation.
- **Multi-Protocol Campaign Correlator**: Cross-protocol adversary session aggregation with Bayesian scoring and velocity multipliers.
- **Kubernetes Helm Chart**: Production-ready deployment (`deploy/helm/shinkiro`) with strict security contexts (`readOnlyRootFilesystem`, `runAsNonRoot`, `drop: [ALL]`).
- **Comprehensive Fuzzing Suite**: Continuous native Go fuzz tests (`testing.F`) across all protocol parsers via `make fuzz`.
- **Supply Chain Security**: Sigstore Cosign keyless OIDC signing, Anchore Syft SBOM generation (SPDX & CycloneDX), and SLSA build provenance in CI.
- **Telnet IoT Botnet Decoy (`:2323`)**: Emulates BusyBox v1.31.1 embedded Linux router, handles IAC negotiation, and captures Mirai botnet credentials.
- **MQTT Broker Decoy (`:1883`)**: MQTT v3.1.1 protocol parser trapping unauthorized IoT client connections and command injections.
- **Raw PCAP Forensic Engine**: Zero-copy packet capture writer storing malicious payloads in standard libpcap 2.4 format (`data/dump.pcap`).
- **SMB/CIFS Decoy (`:4445`)**: NetBIOS session and SMBv2 negotiate parser detecting EternalBlue reconnaissance.
- **Decoys Matrix Documentation**: Comprehensive MITRE ATT&CK mapping and threat score taxonomy in `docs/decoys/decoy-matrix.md`.


## [v0.2.0] - 2026-09-04

### Added
- **AWS IMDS Decoy (`:8169`)**: Full EC2 Instance Metadata Service emulator (IMDSv1 & IMDSv2) designed to trap SSRF attacks targeting IAM role credentials (`/latest/meta-data/iam/security-credentials/`).
- **Native C eBPF / XDP Driver**: Low-level kernel packet filtering engine (`internal/ebpf/c/xdp_drop.c`) dropping blacklisted malicious packets at the network interface before socket allocation.
- **STIX 2.1 Threat Intelligence Exporter**: Native command `shinkiro stix` transforming observed honeypot interactions into standardized STIX 2.1 JSON bundles.
- **Offline GeoIP & Autonomous System Resolver**: Embedded fast-lookup engine enriching telemetry with country, city, ASN, and organization without external network dependencies.
- **Distributed Cluster Mesh Hub**: Multi-node HTTP aggregation engine (`shinkiro cluster hub`) allowing edge sensors to synchronize threat feeds to a centralized controller.

## [v0.1.0] - 2026-09-04

### Added
- Initial release of Shinkiro deception engine in Go.
- Core Multiplexer and in-memory decoys (SSH, Redis, Docker, HTTP, PostgreSQL, K8s).
- Live Bubbletea Terminal Dashboard (`shinkiro tui`).
- Dynamic firewall mitigation (`iptables`, `nftables`).
