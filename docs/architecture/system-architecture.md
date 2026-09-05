# Shinkiro Cyber Deception & Threat Intelligence Architecture

```mermaid
graph TD
    %% Adversary Vector
    subgraph Adversaries ["🌐 Adversary Traffic Vectors"]
        A1["SSH / Telnet Brute Force<br/>(Ports 2222, 2323)"]
        A2["Cloud & Container Probes<br/>(AWS IMDS :8169, Docker :2375, K8s :6443)"]
        A3["Database Recon<br/>(PostgreSQL :5432, Redis :6379, Mongo :27017)"]
        A4["IoT & Lateral Movement<br/>(MQTT :1883, SMB :4445, SMTP :2525, DNS :1053)"]
        A5["Industrial Control Systems (OT)<br/>(Modbus/TCP :502)"]
    end

    %% Core Multiplexer
    subgraph Core ["🛡️ Shinkiro Core In-Memory Multiplexer"]
        Mux["Listener Multiplexer Engine<br/>- Strict Read/Write Timeouts<br/>- Slowloris Mitigation<br/>- Memory-Jailed Goroutines"]
        PCAP["Raw Libpcap 2.4 Forensics<br/>(data/dump.pcap)"]
    end

    A1 -->|TCP/UDP| Mux
    A2 -->|TCP/UDP| Mux
    A3 -->|TCP/UDP| Mux
    A4 -->|TCP/UDP| Mux
    A5 -->|TCP| Mux
    Mux -.->|Zero-Copy Frame Dump| PCAP

    %% Decoy Layer
    subgraph Decoys ["🎭 High-Interaction Protocol Decoys"]
        direction TB
        D_SSH["SSH (VirtualFS Bash & Jitter)"]
        D_Telnet["Telnet (BusyBox Mirai)"]
        D_Redis["Redis (RESP & Lua EVAL)"]
        D_Docker["Docker API (Cryptominer Trap)"]
        D_K8s["K8s API (RBAC Probes)"]
        D_AWS["AWS IMDS (SSRF Canary Keys)"]
        D_PG["PostgreSQL (Auth Capture)"]
        D_Mongo["MongoDB (OP_MSG BSON)"]
        D_Elastic["Elasticsearch (Indices)"]
        D_MQTT["MQTT 3.1.1 (IoT Broker)"]
        D_SMB["SMBv2 (EternalBlue Recon)"]
        D_SMTP["SMTP (Spam / Phishing)"]
        D_DNS["DNS (Subdomain Enum)"]
        D_HTTP["HTTP (Canary & Admin Traps)"]
        D_Modbus["Modbus/TCP (ICS/SCADA PLC)"]
    end

    Mux --> D_SSH
    Mux --> D_Telnet
    Mux --> D_Redis
    Mux --> D_Docker
    Mux --> D_K8s
    Mux --> D_AWS
    Mux --> D_PG
    Mux --> D_Mongo
    Mux --> D_Elastic
    Mux --> D_MQTT
    Mux --> D_SMB
    Mux --> D_SMTP
    Mux --> D_DNS
    Mux --> D_HTTP
    Mux --> D_Modbus

    %% Telemetry & Intel Engine
    subgraph Telemetry ["⚡ Real-Time Intelligence & Attribution Pipeline"]
        GeoIP["Offline GeoIP & ASN Engine"]
        Hasher["SHA-256 Payload Hasher"]
        Mitre["MITRE ATT&CK Mapper (TTPs)"]
        Corr["Campaign Correlator (Multi-Decoy)"]
        Score["Dynamic Threat Scoring (0-100)"]
    end

    D_SSH -->|Event| Hasher
    D_Telnet -->|Event| Hasher
    D_Redis -->|Event| Hasher
    D_Docker -->|Event| Hasher
    D_K8s -->|Event| Hasher
    D_AWS -->|Event| Hasher
    D_PG -->|Event| Hasher
    D_Mongo -->|Event| Hasher
    D_Elastic -->|Event| Hasher
    D_MQTT -->|Event| Hasher
    D_SMB -->|Event| Hasher
    D_SMTP -->|Event| Hasher
    D_DNS -->|Event| Hasher
    D_HTTP -->|Event| Hasher
    D_Modbus -->|Event| Hasher

    Hasher --> Mitre
    Mitre --> GeoIP
    GeoIP --> Corr
    Corr --> Score

    %% Outputs & Automated Defense
    subgraph Outputs ["📊 Integration & Active Mitigation"]
        SOAR["SOAR-Lite Engine<br/>(playbooks.yaml)"]
        SIEM["SIEM & Feeds<br/>(ArcSight CEF / Syslog / STIX 2.1 / ECS / ThreatFox)"]
        Prom["Prometheus Metrics<br/>(:9100/metrics)"]
        TUI["Bubbletea Terminal UI<br/>(shinkiro tui)"]
        Webhook["SecOps Webhooks<br/>(Slack Block Kit / Discord)"]
        Drop["Kernel-Level Defense<br/>- Native eBPF / XDP Filter<br/>- nftables / iptables Sets"]
    end

    Score --> SOAR
    Score --> SIEM
    Score --> Prom
    Score --> TUI
    Score --> Webhook
    SOAR -->|Automated Playbook Action| Drop
    Score -->|Score >= 80| Drop
```

---

## Data Flow Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as 🦹 Adversary
    participant Mux as 🛡️ Multiplexer
    participant Decoy as 🎭 Protocol Decoy
    participant Intel as ⚡ Threat Engine
    participant XDP as 🛑 Kernel eBPF/XDP

    Attacker->>Mux: Connect (e.g. TCP :2222 or :6379)
    Mux->>Mux: Set 30s deadline, enforce memory jail
    Mux->>Decoy: Dispatch socket connection
    Decoy->>Attacker: Send authentic banner/challenge
    Attacker->>Decoy: Send exploit payload / credentials
    Decoy->>Intel: Dispatch structured telemetry event
    par Parallel Ingestion
        Intel->>Intel: Compute SHA-256 payload hash
        Intel->>Intel: Offline GeoIP & ASN lookup
        Intel->>Intel: Update IP threat score (e.g. 95)
    end
    Decoy->>Attacker: Return realistic simulated error/shell
    alt Threat Score >= 80
        Intel->>XDP: Stage IP in eBPF blacklist_map
        Note over XDP,Attacker: Subsequent packets dropped at NIC before OS socket allocation
    end
```
