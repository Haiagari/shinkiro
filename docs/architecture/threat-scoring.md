# Threat Scoring & IoC Attribution Matrix

Shinkiro computes a cumulative threat score (0–100) per observed remote IP address across all active decoy protocols.

## Scoring Rules

| Protocol / Event | Action Type | Base Score | Severity | Triggered Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **TCP Connect / Ping** | `CONNECT` / `PING` | 10 | `LOW` | Logged in JSONL audit |
| **HTTP Web Recon** | `GET /` (Generic probe) | 20 | `LOW` | Rate limiting monitoring |
| **SSH Handshake** | `SSH_BANNER_EXCHANGE` | 40 | `MEDIUM` | IP staged in tracking LRU |
| **Redis Command** | `INFO` / `PING` | 40 | `MEDIUM` | Cluster recon flagged |
| **Docker API Ping** | `GET /_ping`, `GET /version` | 50 | `MEDIUM` | Daemon exposure scan |
| **PostgreSQL Auth** | `PG_AUTH_PROBE` | 70 | `HIGH` | Database brute force alert |
| **K8s Discovery** | `GET /api`, `GET /apis` | 75 | `HIGH` | Cluster recon alert |
| **HTTP Trap Hit** | `GET /.env`, `GET /.git/config` | 80 | `HIGH` | **Immediate Firewall DROP** |
| **AWS IMDS SSRF** | `PUT /latest/api/token` | 90 | `CRITICAL` | **Immediate Firewall DROP** |
| **AWS IAM Role Exfil** | `GET /latest/meta-data/iam/...` | 100 | `CRITICAL` | **Kernel XDP DROP + STIX** |
| **Docker Crypto-miner** | `POST /containers/create` | 95 | `CRITICAL` | **Kernel XDP DROP + STIX** |
| **SSH RCE / Shell** | `curl`, `wget`, `bash -i` | 100 | `CRITICAL` | **Kernel XDP DROP + STIX** |
| **Redis Lua Injection** | `EVAL` script payload | 95 | `CRITICAL` | **Kernel XDP DROP + STIX** |

## Kernel & Firewall Mitigation Thresholds

- **Score >= 80**: Staged in `iptables` / `nftables` blackhole sets.
- **Score >= 95**: Ingested directly into the **eBPF XDP `blacklist_map`** hash table to drop packets at NIC ingress before operating system socket allocation.
