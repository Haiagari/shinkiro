# Threat Scoring, Campaign Correlation & IoC Attribution Engine

**Product:** Shinkiro (蚩気楼)  
**Package:** `internal/intel` & `internal/soar`  
**Note:** Hot-path latency claims below are design targets — run `make bench` for measured numbers; do not treat historical invented ns/op tables as CI truth.

Related: [`event-pipeline.md`](event-pipeline.md) · [`campaign-correlator-v2.md`](campaign-correlator-v2.md) · [`../threat-intel/geolite2-geoip.md`](../threat-intel/geolite2-geoip.md)

---

## 1. Threat Scoring Architecture & Philosophy

A honeynet that emits unprioritized alerts creates SOC fatigue. Shinkiro assigns:

1. **Discrete Event Severity:** `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` (as emitted by decoys / intel helpers).
2. **Threat Score (0 to 100):** Normalized integer indicating risk and confidence.
3. **Cumulative Reputation Score:** Aggregated risk per IP in an in-memory map.
4. **MITRE ATT&CK TTP Binding:** Association with enterprise and ICS tactics/techniques.
5. **Campaign Session Clustering:** Multi-protocol attacker campaign association (`internal/intel/correlator.go` — **v2 rule-based**, not ML).

Threat scores themselves are primarily **assigned by decoy handlers** when they emit events. The pipeline **Score** stage enriches with MITRE (if missing) and optional MaxMind GeoIP — it does not invent a parallel scorer.

```mermaid
graph LR
    subgraph Ingress ["Decoy Interaction"]
        Ev["Raw Network Event<br/>(Decoy, Action, Payload)"]
    end

    subgraph Evaluation ["Threat Scoring Engine"]
        Base["Base Score Evaluator"]
        Mitre["MITRE TTP Categorization"]
        Rep["Cumulative IP Score Tracker"]
        Corr["Campaign Correlator v2"]
        
        Ev --> Base
        Base --> Mitre
        Mitre --> Rep
        Rep --> Corr
    end

    subgraph Actions ["Response Thresholds (implemented)"]
        Pass["Lower scores: Passive baiting / log"]
        Review["Mid scores: SOAR alert hooks"]
        Block["Higher scores: block_ip hook + export text"]
        Export["Export nftables/iptables/sample eBPF script text<br/>(operator applies — no live XDP attach)"]
    end

    Corr --> Pass
    Corr --> Review
    Corr --> Block
    Corr --> Export
```

---

## 2. Threat Scoring Matrix by Protocol & Action

Representative mappings (verify against decoy code for exact action strings):

| Protocol / Vector | Action Identifier | Base Score | Severity | MITRE Tactic & Technique | Operational Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TCP / Ping** | `TCP_CONNECT`, `PING` | 10 | `INFO` | `TA0043` / `T1595` | Logged passively in JSONL |
| **HTTP Web Recon** | `GET /`, `HEAD /` | 20 | `LOW` | `TA0043` / `T1595` | Sliding session; often crawler noise |
| **DNS Query** | `DNS_A_LOOKUP` | 30 | `LOW` | `TA0011` / `T1071.004` | Intercepted domain query; GeoIP optional |
| **SSH Handshake** | `SSH_PROBE_CONNECT` | 40 | `MEDIUM` | `TA0043` / `T1595` | Banner exchange |
| **Redis Command** | `INFO`, `PING` | 40 | `MEDIUM` | `TA0007` / `T1082` | Topology metadata query |
| **Docker API Ping** | `GET /_ping`, `GET /version` | 50 | `MEDIUM` | `TA0007` / `T1613` | Exposed daemon recon |
| **Elasticsearch** | `GET /_cat/indices` | 60 | `MEDIUM` | `TA0007` / `T1083` | Index enumeration |
| **PostgreSQL Auth** | `PG_AUTH_PROBE` | 70 | `HIGH` | `TA0006` / `T1110` | Auth attempt; credentials logged |
| **Kubernetes Recon**| `GET /api/v1/namespaces` | 75 | `HIGH` | `TA0007` / `T1613` | Anonymous RBAC / secrets paths |
| **Modbus PLC Read** | `MODBUS_FC03_READ_HOLDING_REGISTERS` | 75 | `HIGH` | `TA0108` / `T0858` | ICS reconnaissance |
| **SSH Login Success**| `SSH_LOGIN_SUCCESS_DECOY` | 75 | `HIGH` | `TA0001` / `T1078` | Login into VirtualFS shell |
| **HTTP Config Trap**| `GET /.env`, `GET /.git/config` | 80 | `HIGH` | `TA0001` / `T1190` | Secret-path scanning; SOAR may `block_ip` |
| **Redis Config Dump**| `CONFIG GET *` | 85 | `CRITICAL` | `TA0006` / `T1552` | Config dump / persistence prep |
| **Jenkins / WP Admin**| `POST /wp-login.php`, `Jenkins` | 85 | `CRITICAL` | `TA0006` / `T1110` | Credential stuffing |
| **SSH Shell Command**| `cat /etc/passwd`, `whoami` | 85 | `HIGH` | `TA0002` / `T1059.004` | Interactive VirtualFS exploration |
| **AWS IMDS Token** | `PUT /latest/api/token` | 90 | `CRITICAL` | `TA0006` / `T1552.005` | IMDSv2 token acquisition |
| **Modbus Coil Write**| `MODBUS_FC05_WRITE_SINGLE_COIL` | 95 | `CRITICAL` | `TA0108` / `T0855` | OT write attempt |
| **Redis Lua RCE** | `EVAL "redis.call(...)"` | 95 | `CRITICAL` | `TA0002` / `T1059` | Sandbox escape attempt |
| **Docker Miner** | `POST /containers/create` | 95 | `CRITICAL` | `TA0002` / `T1609` | Container create attempt |
| **AWS IAM Exfil** | `GET /latest/meta-data/iam/...` | 100 | `CRITICAL` | `TA0006` / `T1552.005` | IAM credential path harvest |
| **SSH Dropper** | `curl`, `wget`, `bash -i`, `python` | 100 | `CRITICAL` | `TA0002` / `T1059` | Remote payload style commands |

---

## 3. Multi-Protocol Campaign Correlation (v2)

See **[`campaign-correlator-v2.md`](campaign-correlator-v2.md)** for full operator notes.

Summary algorithm:

1. On event from `RemoteIP`, look up an active `Campaign`.
2. If absent or expired (outside session window), initialize `camp-<IP>-<timestamp>`.
3. If active, update `LastSeen`, decoy hop path, `MaxThreatScore`, MITRE IDs, usernames, commands, grouping reasons.

```bash
./bin/shinkiro campaigns --format json --window 2h
```

Example shape (illustrative; geo fields only appear when MaxMind enrichment ran):

```json
{
  "id": "camp-198.51.100.25-1788642000",
  "attacker_ip": "198.51.100.25",
  "decoys_targeted": ["ssh", "redis", "modbus"],
  "hop_path": "ssh -> redis -> modbus",
  "total_events": 12,
  "max_threat_score": 95,
  "grouping": ["same_src_ip", "session_window", "decoy_hop"]
}
```

---

## 4. Firewall & Sample Kernel Rule Export

Shinkiro stages mitigation via SOAR hooks and **text exporters**. It does **not** program a live XDP map from userland.

```bash
./bin/shinkiro export --format nftables --threshold 80
./bin/shinkiro kernel   # sample script text only
```

- Sample C: `internal/ebpf/c/xdp_drop.c`
- Script text: `FilterManager.RenderScript()`
- Loading/attaching those artifacts is an **operator** responsibility

Live SOAR apply (`--apply`) executes `nft`/`iptables` command text — still not BPF map updates.

---

## 5. SOAR-Lite Playbook Automation Engine

Package `internal/soar` loads YAML into `PlaybookConfig{ Rules []Rule }` where each rule uses **`if` / `then`**.

### 5.1. Real Playbook Schema (`playbooks.yaml`)

```yaml
rules:
  - name: ssh-credential-stuffing-autoblock
    enabled: true
    if:
      decoy: ssh
      min_score: 75
      action_match: LOGIN
    then:
      - type: block_ip
      - type: alert

  - name: redis-exploitation-immediate-ban
    enabled: true
    if:
      decoy: redis
      min_score: 80
      action_match: CONFIG
    then:
      - type: block_ip
      - type: alert

  - name: rapid-recon-scanning-ratelimit
    enabled: true
    if:
      decoy: "*"
      threshold: 5
      window_sec: 30
    then:
      - type: block_ip
      - type: alert
```

Supported action types in code today: **`block_ip`**, **`alert`** / **`notify`**, **`tag`**.

**Dry-run default** for `block_ip`; live only with `--apply` / `SHINKIRO_SOAR_APPLY=1`. Details: [`event-pipeline.md`](event-pipeline.md).

---

## 6. GeoIP, Decay & Velocity Notes

### 6.1. Optional MaxMind GeoIP

Enrichment writes `geo_country` / `geo_city` / `geo_asn` / `geo_org` when a `.mmdb` is loaded. Private/loopback → `LOCAL`. **No invented coordinates.** Product works with GeoIP disabled. Guide: [`geolite2-geoip.md`](../threat-intel/geolite2-geoip.md).

### 6.2. Temporal decay & velocity

Reputation may decay over inactivity; repeated probing can inflate scores. SOAR also supports explicit `threshold` + `window_sec` rate gates. Treat older numeric formulas as illustrative — verify constants in `internal/intel` before citing SLAs.

### 6.3. Private / local handling

Operators should maintain firewall allowlists separately — Shinkiro does not ship a full enterprise NAC CIDR policy engine.
