# Shinkiro System Architecture & Technical Specification

**Product:** Shinkiro (蜃気楼)  
**License:** AGPL-3.0-only  
**Language:** Go 1.24+ (single binary)

---

## 1. System Design Goals & Principles

1. **Zero Host Mutation:** Deceptive protocols must not execute host binaries or write attacker-controlled files for shell semantics. State stays in synthetic in-memory structures.
2. **Fail-Closed Security Posture:** Malformed frames / parser failures terminate the socket without stack traces to the client.
3. **Measurable Hot Path:** Prefer measured `go test -bench` results over undocumented SLA nanoseconds.
4. **Actionable SOC Interoperability:** CEF, Syslog, STIX 2.1, ECS exporters; MITRE tagging.
5. **Exportable Active Defense:** nftables/iptables/sample eBPF **text** + SOAR `block_ip` / `alert` — not a silent live XDP attach.

---

## 2. Component Topology & Data Flow

```mermaid
graph TD
    subgraph AdversaryPlane ["🌐 Adversary Vectors"]
        Attacker["Adversary Traffic"]
    end

    subgraph CoreMultiplexer ["🛡️ In-Memory Multiplexer Engine"]
        Mux["Core Listener Multiplexer<br/>• Connection Deadlines<br/>• Slowloris Mitigation"]
        PCAP["internal/pcap Writer<br/>(not wired in main)"]
    end

    subgraph DecoyPlane ["🎭 15 High-Interaction Protocol Decoys"]
        D_SSH["SSH :2222"]
        D_Telnet["Telnet :2323"]
        D_Modbus["Modbus/TCP :502"]
        D_Redis["Redis :6379"]
        D_Docker["Docker :2375"]
        D_K8s["Kubernetes :6443"]
        D_HTTP["HTTP :8080"]
        D_Postgres["PostgreSQL :5432"]
        D_Mongo["MongoDB :27017"]
        D_Elastic["Elasticsearch :9200"]
        D_IMDS["AWS IMDS :8169"]
        D_MQTT["MQTT :1883"]
        D_SMB["SMBv2 :4445"]
        D_SMTP["SMTP :2525"]
        D_DNS["DNS :1053"]
    end

    subgraph IntelPipeline ["⚡ Intelligence & Attribution"]
        Events["Audit Stream (events.jsonl)"]
        Geo["Heuristic GeoIP prefixes"]
        Mitre["MITRE ATT&CK Mapper"]
        Corr["Campaign Correlator"]
        Score["Threat Scorer (0-100)"]
    end

    subgraph ActiveDefense ["🚀 SOAR & Exporters"]
        SOAR["SOAR-Lite (rules/if/then)"]
        Kernel["Rule text: eBPF sample / nftables / iptables"]
        Hub["Cluster HTTP ingest hub"]
    end

    subgraph SecOpsInterfaces ["📊 SecOps Integrations"]
        CEF["CEF"]
        Syslog["Syslog"]
        STIX["STIX 2.1"]
        ECS["ECS"]
        ThreatFox["ThreatFox helpers"]
        TUI["TUI"]
        Prom["Prometheus :9100"]
        Webhooks["Webhook helpers"]
    end

    Attacker --> Mux
    Mux --> DecoyPlane
    Mux -.->|not wired| PCAP

    DecoyPlane --> Events
    Events --> Geo
    Geo --> Mitre
    Mitre --> Corr
    Corr --> Score

    Score --> SOAR
    SOAR --> Kernel
    Score --> Kernel
    Hub -.-> Score

    Score --> CEF
    Score --> Syslog
    Score --> STIX
    Score --> ECS
    Score --> ThreatFox
    Score --> TUI
    Score --> Prom
    Score --> Webhooks
```

---

## 3. Package & Module Architecture

```text
internal/
├── adversary/          # Automated red-team simulate suite
├── canary/             # Canary token helpers
├── cluster/            # HTTP ingest hub (NOT UDP gossip)
├── config/             # YAML parser — runtime key services:
├── core/               # Multiplexer & connection lifecycle; Benchmark* tests
├── decoys/             # Unified Decoy interface & 15 protocol emulators
│   ├── aws/ dns/ docker/ elastic/ http/ k8s/
│   ├── modbus/ mongo/ mqtt/ postgres/ redis/
│   ├── smb/ smtp/ ssh/ telnet/
├── defense/            # iptables & nftables ruleset text generator
├── ebpf/               # Sample C + RenderScript exporter (NOT live loader)
├── intel/              # Telemetry, scoring, MITRE, correlator
│   ├── ecs/            # ECS serializer
│   ├── geoip/          # Heuristic / demo prefix resolver (NOT MaxMind)
│   ├── siem/           # CEF & Syslog exporters
│   └── stix/           # STIX 2.1 bundle generator
├── metrics/            # Prometheus helpers
├── pcap/               # Libpcap 2.4 writer (NOT wired in cmd/main)
├── soar/               # Playbook engine (block_ip, alert, tag)
├── tui/                # Bubbletea dashboard
└── webhook/            # Slack / Discord helpers
```

---

## 4. Operational CLI Interface

```bash
shinkiro up [--config config.yaml]
shinkiro tui
shinkiro cef
shinkiro syslog
shinkiro ecs
shinkiro stix
shinkiro export --format nftables     # text export
shinkiro export --format iptables     # text export
shinkiro kernel                       # sample eBPF / rule script text
shinkiro canary generate --label prod-cluster-secret
shinkiro simulate --host 127.0.0.1
shinkiro cluster hub                  # HTTP ingest on configured port
```

---

## 5. Security & Runtime Hardening

- **Seccomp file:** `deploy/security/seccomp.json` for operators to apply.
- **Supply chain:** Releases build with `-trimpath` / stripped ldflags; Cosign **`sign-blob`** on `checksums.txt`; Syft SPDX + CycloneDX SBOMs. **No SLSA Level 3 provenance workflow.**
- **Fuzzing:** Selected `testing.F` targets via `make fuzz`.
- **Deploy caveats:** Dockerfile and Helm chart exist; GHCR one-liner and full `services:` config mounts are incomplete until a deploy PR.

---

## 6. Go Package Integration

Prefer copying patterns from `cmd/shinkiro/main.go` — it is the authoritative wiring for decoys, SOAR, metrics, cluster hub, and exporters. Public/internal APIs evolve with the binary; do not invent alternate constructor signatures in docs without checking the source.

### Decoy lifecycle (conceptual)

```mermaid
stateDiagram-v2
    [*] --> Initialized: NewDecoy(...)
    Initialized --> Listening: Start(ctx)
    Listening --> ConnectionAccepted: Accept()
    ConnectionAccepted --> DeadlineEnforced: SetDeadline
    DeadlineEnforced --> FrameParsing: Read
    FrameParsing --> ThreatScored: Evaluate
    ThreatScored --> SyntheticResponse: Write
    SyntheticResponse --> ConnectionClosed: Close
    ConnectionClosed --> Listening
    Listening --> [*]: Stop()
```

---

## 7. Metrics & Observability (`:9100/metrics`)

Prometheus helpers live under `internal/metrics`. Treat metric names in dashboards as best-effort documentation — verify exporters in code before depending on a specific time series (including any historical `shinkiro_ebpf_drops_total` style counters that implied a live XDP path).
