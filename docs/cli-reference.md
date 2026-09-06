# CLI Reference

**Binary:** `shinkiro` (`cmd/shinkiro`)  
**Help:** run with no args or unknown command → prints banner + usage (`usage.go`), exits `1`.  
**Version:** `shinkiro version` | `-v` | `--version`

This page mirrors flags and env vars **as implemented**. Cross-links: [operator-guide](operator-guide.md), [event-pipeline](architecture/event-pipeline.md), [cluster-hub](architecture/cluster-hub.md), [campaigns/feeds/coverage](cli-campaigns-feeds-coverage.md).

---

## Command map

| Command | Purpose |
| :--- | :--- |
| `up` | Headless decoy mesh + pipeline |
| `tui` | Interactive Bubbletea dashboard (same pipeline) |
| `canary generate` | HMAC-signed synthetic AWS honeytoken |
| `campaigns` | Rebuild correlator v2 campaigns from JSONL |
| `threatfox` | Query ThreatFox HTTP API |
| `abuseipdb` | AbuseIPDB IP check |
| `coverage` / `attack-coverage` | ATT&CK coverage from decoy-matrix (+ optional runtime mapper) |
| `geoip` | Ops test MaxMind lookup |
| `export` | Firewall rule **text** from malicious IPs |
| `stix` | STIX 2.1 JSON bundle from events |
| `ecs` | ECS v8.x JSON export |
| `cef` | ArcSight CEF lines |
| `syslog` | RFC5424 Syslog lines |
| `cluster hub` | Hub-and-spoke HTTP hub (**not** gossip) |
| `kernel` / `ebpf` | Sample eBPF / nft / iptables **script text** (not a live loader) |
| `simulate` / `attack` | Red-team probe suite vs local mesh |
| `version` | Print ldflags version/commit/date |

---

## Global / shared options & environment

Many flags are command-local. Shared operational env:

| Variable | Effect |
| :--- | :--- |
| `SHINKIRO_SOAR_APPLY=1` | Same as `--apply` — live firewall exec / webhook POST |
| `SHINKIRO_SOAR_BLOCK_FORMAT` | `nftables` (default) \| `iptables` \| `cidr` |
| `SHINKIRO_SOAR_BLOCK_WEBHOOK` | Optional URL for `block_ip` JSON POST when applying |
| `SHINKIRO_PCAP_THRESHOLD` | On-demand PCAP score gate (default `80`) |
| `SHINKIRO_PCAP_DIR` | PCAP output directory (default `data/pcap`) |
| `SHINKIRO_WEBHOOK_URL` | Slack/Discord alert webhook for critical events |
| `SHINKIRO_GEOLITE2_PATH` | Optional MaxMind GeoLite2/GeoIP2 `.mmdb` |
| `SHINKIRO_CLUSTER_TOKEN` | Shared secret for cluster join/ingest (empty = lab insecure) |
| `THREATFOX_API_KEY` | ThreatFox Auth-Key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |

Config file: commands that load config use **`config.yaml`** in the process CWD (`config.LoadConfig("config.yaml")`). There is no global `--config` parser wired in `up` today despite older usage text mentioning it — place `config.yaml` next to the working directory.

---

## `shinkiro up`

Start all registered decoys, feed events into the pipeline, print console telemetry.

```bash
shinkiro up [--apply] [--geoip-db PATH]
```

| Flag | Description |
| :--- | :--- |
| `--apply` | Live-execute SOAR `block_ip` firewall commands (default: dry-run) |
| `--geoip-db PATH` | MaxMind `.mmdb` (overrides `SHINKIRO_GEOLITE2_PATH`) |

**Registers 15 decoys:** ssh, redis, docker, http, postgres, k8s, aws, mongo, elastic, smtp, dns, smb, telnet, mqtt, modbus (see `up.go`).

**Pipeline:** Score (MITRE + optional GeoIP) → Correlate → Playbook → Sink (metrics, webhook, PCAP, JSONL, console).

---

## `shinkiro tui`

Same as `up` with Bubbletea UI instead of console lines.

```bash
shinkiro tui [--apply] [--geoip-db PATH]
```

Keys: `↑↓`/`jk`, `Tab`, `b` block, `p` pcap, `s` simulate, `c` canary, `r` refresh, `?` help, `q` quit. See [`architecture/tui-operator.md`](architecture/tui-operator.md).

---

## `shinkiro canary`

```bash
shinkiro canary generate [--label LABEL]
# `generate` token is optional (stripped if present)
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--label` | `canary-prod-seed` | Attribution tag for HMAC AWS-style honeytoken |

Prints JSON token material from `internal/canary` — **not** live IAM credentials.

---

## `shinkiro campaigns`

Rebuild correlator v2 from persisted events (works without a live mesh).

```bash
shinkiro campaigns [--format table|json] [--events PATH] [--window DURATION]
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--format` | `table` | `table` or `json` |
| `--events` | config `audit_log_path` or `data/events.jsonl` | JSONL path |
| `--window` | `2h` | Session window for regrouping |

Rule-based (same IP + window + hop path) — **not ML**.

---

## `shinkiro threatfox`

```bash
shinkiro threatfox --search <ioc> [--format table|json]
shinkiro threatfox --days <1-7> [--format table|json]
```

Requires `THREATFOX_API_KEY`. Exits non-zero if key missing or args invalid. No fake IoCs.

---

## `shinkiro abuseipdb`

```bash
shinkiro abuseipdb --ip <addr> [--max-age 90] [--format table|json]
```

Requires `ABUSEIPDB_API_KEY`.

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--ip` | (required) | IP to check |
| `--max-age` | `90` | Max age days for reports |
| `--format` | `table` | `table` \| `json` |

---

## `shinkiro coverage` / `attack-coverage`

```bash
shinkiro coverage [--format table|json] [--runtime-mapper]
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--format` | `table` | `table` \| `json` |
| `--runtime-mapper` | false | Also include `MapToMitre` heuristics |

Maps decoy-matrix technique tags — does not invent ATT&CK IDs.

---

## `shinkiro geoip`

```bash
shinkiro geoip --ip <addr> [--geoip-db PATH] [--format table|json]
```

| Flag | Description |
| :--- | :--- |
| `--ip` | Required |
| `--geoip-db` | Overrides `SHINKIRO_GEOLITE2_PATH` |
| `--format` | `table` (default) \| `json` |

When disabled: prints status + empty fields + hint. Never invents coordinates.

---

## `shinkiro export`

```bash
shinkiro export [--format iptables|nftables|cidr] [--threshold 80]
# Usage also documents: shinkiro export blocklist  (subcommand word optional in practice — flags drive format)
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--format` | `iptables` | Firewall syntax for generated **text** |
| `--threshold` | `80` | Minimum threat score for IP inclusion |

Reads `data/events.jsonl` via intel engine. Does **not** apply rules.

---

## `shinkiro stix` / `ecs` / `cef` / `syslog`

```bash
shinkiro stix      # STIX 2.1 bundle from data/events.jsonl (empty bundle if missing)
shinkiro ecs       # ECS JSON batch (RecentEvents 500) using config node_name
shinkiro cef       # One CEF line per recent event
shinkiro syslog    # One RFC5424 line per recent event
```

No additional flags in current handlers. Pipe to files or SIEM collectors as needed.

---

## `shinkiro cluster hub`

Hub-and-spoke HTTP aggregation — **not** gossip/mesh.

```bash
shinkiro cluster hub [--port 9090] [--token SECRET] [--tls-cert PATH] [--tls-key PATH]
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--port` | `9090` | Listen port |
| `--token` | env `SHINKIRO_CLUSTER_TOKEN` | Shared secret; empty = lab insecure |
| `--tls-cert` / `--tls-key` | unset | Optional native TLS (both required together) |

Endpoints: `/healthz`, `/readyz`, `POST /api/v1/cluster/join`, `POST /api/v1/cluster/ingest`, `GET /api/v1/cluster/nodes`. See [`architecture/cluster-hub.md`](architecture/cluster-hub.md).

---

## `shinkiro kernel` / `ebpf`

```bash
shinkiro kernel [rules]
# alias: shinkiro ebpf
```

Emits sample XDP-oriented / nftables / iptables **script text** via `internal/ebpf.FilterManager.RenderScript()`.  
**Does not** attach XDP, open BPF maps, or load kernel programs.

---

## `shinkiro simulate` / `attack`

```bash
shinkiro simulate [--host 127.0.0.1]
# alias: shinkiro attack
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--host` | `127.0.0.1` | Target host running the mesh |

Runs `adversary.DefaultScenarios()` with ~2s per-scenario timeout.

---

## `shinkiro version`

```bash
shinkiro version
shinkiro -v
shinkiro --version
```

Prints version string from ldflags (`dev` / `none` / `unknown` when built without injection).

---

## Exit status

| Situation | Exit |
| :--- | :--- |
| No arguments | `1` + usage |
| Unknown command | `1` + usage |
| Missing required flags / API keys (feeds, geoip, …) | `1` |
| Successful command | `0` (unless handler exits otherwise) |

---

## Related short guides

- [`cli-campaigns-feeds-coverage.md`](cli-campaigns-feeds-coverage.md) — campaigns / ThreatFox / AbuseIPDB / coverage examples  
- [`threat-intel/geolite2-geoip.md`](threat-intel/geolite2-geoip.md) — GeoIP enablement  
- [`threat-intel/threatfox-abuseipdb.md`](threat-intel/threatfox-abuseipdb.md) — feed API details  
