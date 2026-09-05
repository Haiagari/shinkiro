# Decoy Protocols & Emulation Matrix

Shinkiro deploys an ultra-lightweight, zero-footprint, in-memory mesh of high-interaction deception lures designed to mimic critical enterprise infrastructure and capture adversary tactics, techniques, and procedures (TTPs) aligned with MITRE ATT&CK.

| Decoy Service | Protocol | Default Port | Emulated Behavior & Exploitation Surface | MITRE Technique | Threat Score |
|---|---|---|---|---|---|
| **SSH** | TCP | `2222` / `22` | OpenSSH 9.2p1 banner, in-memory VirtualFS bash shell, canary file `/root/.env` | T1078, T1059.004 | 90–100 |
| **Telnet** | TCP | `2323` / `23` | Embedded Linux router BusyBox v1.31.1, IAC negotiation, Mirai botnet credential harvester | T1078, T1059.004 | 90–100 |
| **MQTT** | TCP | `1883` | MQTT v3.1.1 Broker, CONNECT / PUBLISH / SUBSCRIBE parser, IoT botnet bait | T1078, T1190 | 70–95 |
| **SMB / CIFS** | TCP | `4445` / `445` | NetBIOS & SMBv2 negotiation parser, EternalBlue (MS17-010) & ransomware recon trap | T1021.002, T1210 | 95 |
| **Redis** | TCP | `6379` | RESP 2.0 parser, `INFO`, `SET`, `GET`, `CONFIG`, malicious Lua `EVAL` script hasher | T1059, T1190 | 70–95 |
| **Docker Engine** | HTTP | `2375` | Docker Engine REST API (`/version`, `/_ping`, `/containers/json`, `/containers/create`), XMRig cryptominer trap | T1609, T1496 | 60–100 |
| **Kubernetes API** | HTTP/TLS | `6443` | K8s control plane API (`/version`, `/api/v1/namespaces`, `/api/v1/secrets`), RBAC reconnaissance trap | T1613, T1078.001 | 60–95 |
| **PostgreSQL** | TCP | `5432` | PostgreSQL 3.0 wire protocol handshake, StartupMessage auth harvesting, `MD5`/cleartext capture | T1078.001 | 80 |
| **MongoDB** | TCP | `27017` | BSON wire protocol `OP_MSG` emulator, `isMaster` probe, unauthenticated database access bait | T1078, T1190 | 75 |
| **Elasticsearch** | HTTP | `9200` | Elasticsearch REST API (`/`, `/_cat/indices`, `/_cluster/health`), cluster indexing trap | T1190, T1083 | 65–85 |
| **SMTP / ESMTP** | TCP | `2525` / `25` | Postfix ESMTP banner (`HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`), phishing/spam collector | T1566 | 80 |
| **DNS Server** | UDP | `1053` / `53` | DNS query RFC 1035 parser, subdomain enumeration, C2 covert channel detector | T1071.004, T1568 | 50–90 |
| **AWS IMDS** | HTTP | `8169` / `80` | IMDSv1 & IMDSv2 token generator (`/latest/meta-data/iam/security-credentials/`), SSRF bait with HMAC canary tokens | T1552.005, T1078.004 | 95 |
| **Web / HTTP** | HTTP | `8080` / `80` | High-value web honeytraps (`/.env`, `/.git/config`, `/wp-login.php`, `/actuator/env`, `/phpinfo.php`) | T1190, T1552.001 | 85–90 |
| **Modbus / TCP** | TCP | `502` | ICS/SCADA PLC emulator, MBAP frame decoder, holding registers, coils, unauthorized command bait | T0855, T0858 | 75–95 |

---

## Zero-Footprint Guarantees

1. **No Real Shells**: Attackers never execute binaries on the host OS. Shell sessions run in an isolated in-memory AST and virtual filesystem.
2. **Immutable Sandboxing**: Network listeners execute without kernel privileges (`CAP_DROP=ALL`).
3. **Payload Fingerprinting**: Incoming binaries and commands are hashed in SHA-256 and sent to the STIX/eBPF engine without persistent disk staging.
