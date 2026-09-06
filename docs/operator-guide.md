# Operator Guide

Day-2 operations for a live Shinkiro mesh: TUI, SOAR, PCAP, simulate, and canary. Architecture depth lives in linked docs; this page is the runbook.

---

## 1. Choose a surface

| Mode | Command | When to use |
| :--- | :--- | :--- |
| Headless | `shinkiro up` | Servers, containers, systemd |
| Interactive | `shinkiro tui` | Operator laptop / SOC console |
| Compose lab | `make compose-lab` | Demos / CI smoke |
| Compose edge | `make compose-edge` | Hardened sensor profile |

Both `up` and `tui` share the same decoy registration, pipeline, SOAR BlockApplier, GeoIP resolver, and on-demand PCAP hook.

---

## 2. SOAR dry-run vs apply

**Default is dry-run.** Playbook matches still run; `block_ip` prints would-be firewall commands and does **not** exec `nft`/`iptables` or POST webhooks.

```bash
# Dry-run (safe default)
./bin/shinkiro up
./bin/shinkiro tui

# Live apply (explicit)
./bin/shinkiro up --apply
./bin/shinkiro tui --apply
SHINKIRO_SOAR_APPLY=1 ./bin/shinkiro up
```

| Knob | Values |
| :--- | :--- |
| `SHINKIRO_SOAR_BLOCK_FORMAT` | `nftables` (default), `iptables`, `cidr` |
| `SHINKIRO_SOAR_BLOCK_WEBHOOK` | Optional JSON POST URL when applying |

Playbooks: edit `playbooks.yaml` (`rules` / `if` / `then`). Supported actions: `block_ip`, `alert`/`notify`, `tag`.

**Honesty:** live apply is shell firewall binaries (or webhook) — not silent XDP / BPF map updates.

Details: [`architecture/event-pipeline.md`](architecture/event-pipeline.md).

---

## 3. TUI operator loop

```bash
./bin/shinkiro tui [--apply] [--geoip-db PATH]
```

| Key | Action |
| :--- | :--- |
| `↑`/`k` · `↓`/`j` | Move selection |
| `Tab` | Events ↔ Campaigns |
| `r` | Refresh high-score events (≥50) + campaigns from intel store |
| `b` | SOAR `block_ip` for selected IP (dry-run unless `--apply` / env) |
| `p` | Operator PCAP (`CaptureNow` → `data/pcap/operator-…`) |
| `s` | Adversary simulate vs `127.0.0.1` (mesh must be up — it is, in-process) |
| `c` | Generate AWS canary honeytoken JSON |
| `?` / `h` | Help overlay |
| `esc` / `x` | Clear status / close help |
| `q` / `Ctrl+C` | Quit (stops listeners) |

Full notes: [`architecture/tui-operator.md`](architecture/tui-operator.md). Source of truth for help strings: `internal/tui/keys.go`.

---

## 4. On-demand PCAP

| Trigger | API | When |
| :--- | :--- | :--- |
| Pipeline sink | `MaybeCapture` | `ThreatScore >= SHINKIRO_PCAP_THRESHOLD` (default 80) |
| TUI `p` | `CaptureNow` | Operator selection; ignores score gate |

```bash
export SHINKIRO_PCAP_THRESHOLD=80
export SHINKIRO_PCAP_DIR=data/pcap
ls data/pcap/
# highscore-<ip>-<unix>.pcap  or  operator-…
```

This is **threshold / operator gated**, not continuous mirroring of every socket.

---

## 5. Simulate & canary

```bash
# Mesh listening in another terminal or same host process
./bin/shinkiro simulate --host 127.0.0.1

# HMAC synthetic AWS key material for placement
./bin/shinkiro canary generate --label canary-prod-seed
```

Simulate uses real TCP/HTTP probes from `internal/adversary`. Canary tokens are **not** live cloud credentials.

---

## 6. Campaigns & coverage (offline)

```bash
./bin/shinkiro campaigns --format table
./bin/shinkiro campaigns --format json --window 2h --events data/events.jsonl
./bin/shinkiro coverage
./bin/shinkiro coverage --format json --runtime-mapper
```

Correlator v2 is rule-based (same IP + window + hop path). Coverage maps decoy-matrix tags (+ optional runtime mapper).

---

## 7. Threat feeds & GeoIP (ops)

```bash
export THREATFOX_API_KEY=…
./bin/shinkiro threatfox --search 198.51.100.10

export ABUSEIPDB_API_KEY=…
./bin/shinkiro abuseipdb --ip 198.51.100.10

export SHINKIRO_GEOLITE2_PATH=/var/lib/GeoIP/GeoLite2-City.mmdb
./bin/shinkiro geoip --ip 8.8.8.8
```

Missing keys → non-zero exit, clear error. Missing GeoIP DB → product still runs; enrichment no-op.

---

## 8. Export for SIEM / firewall

```bash
./bin/shinkiro cef
./bin/shinkiro syslog
./bin/shinkiro ecs > /tmp/ecs.json
./bin/shinkiro stix > /tmp/stix.json
./bin/shinkiro export --format nftables --threshold 80
./bin/shinkiro kernel   # sample script text only
```

---

## 9. Cluster hub (multi-sensor)

```bash
export SHINKIRO_CLUSTER_TOKEN="$(openssl rand -hex 32)"
./bin/shinkiro cluster hub --port 9090

# Spoke join / ingest — see architecture/cluster-hub.md
```

Empty token = **lab-only insecure**. Not gossip.

---

## 10. Metrics

If `metrics_port: 9100` in config:

```bash
curl -sf http://127.0.0.1:9100/metrics | head
```

Verify series names in `internal/metrics` before building dashboards. Do not rely on historical counters that implied a live XDP path.

---

## Related

- [Event pipeline](architecture/event-pipeline.md)  
- [CLI reference](cli-reference.md)  
- [Honesty](honesty-limitations.md)  
- [Deploy](../deploy/README.md)  
