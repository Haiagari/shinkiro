# Honesty & Limitations

**Scope:** Explicit list of what Shinkiro **does not** implement, despite historical marketing or earlier drafts. Agents and operators should treat this as binding.

Aligned with post-roadmap PRs **#10–#16** (pipeline/SOAR/PCAP, TUI operator, correlator v2 + feeds, lab/edge + e2e + GHCR, cluster hub auth, MaxMind GeoIP).

---

## 1. Cluster is hub-and-spoke HTTP — not gossip

| Claim | Reality |
| :--- | :--- |
| Encrypted UDP gossip / SWIM / memberlist | **Not implemented** |
| Peer mesh / automatic discovery | **Not implemented** |
| What exists | `shinkiro cluster hub` — central HTTP hub; spokes POST join/ingest |
| Auth | `SHINKIRO_CLUSTER_TOKEN` / `--token`; **empty token = lab-only insecure** |
| TLS | Optional `--tls-cert` + `--tls-key`, or reverse-proxy termination |

See [`architecture/cluster-hub.md`](architecture/cluster-hub.md).

---

## 2. SOAR `block_ip` defaults to dry-run

| Claim | Reality |
| :--- | :--- |
| Silent auto-block in kernel | **No** |
| Default behavior | Prints generated `nftables` / `iptables` command text |
| Live apply | Only with explicit `--apply` **or** `SHINKIRO_SOAR_APPLY=1` |
| Optional webhook | `SHINKIRO_SOAR_BLOCK_WEBHOOK` JSON POST when applying |

See [`architecture/event-pipeline.md`](architecture/event-pipeline.md) and [`operator-guide.md`](operator-guide.md).

---

## 3. GeoIP is optional MaxMind — never invents coordinates

| Claim | Reality |
| :--- | :--- |
| Always-on GeoIP | **No** — unset/missing path → no-op (`GeoIP disabled` once) |
| Demo / heuristic octet countries | **Removed** (PR #16) |
| Invented lat/lon | **Never** |
| What exists | Local `.mmdb` via `SHINKIRO_GEOLITE2_PATH` / `--geoip-db`; CLI `shinkiro geoip` |

See [`threat-intel/geolite2-geoip.md`](threat-intel/geolite2-geoip.md).

---

## 4. Prebuilt binaries are Linux-only

| Platform | Release assets |
| :--- | :--- |
| Linux amd64 / arm64 | `shinkiro-linux-amd64`, `shinkiro-linux-arm64` + checksums + Cosign bundle + SBOMs |
| macOS / Darwin | **No** prebuilt assets — `scripts/install.sh` exits with build-from-source instructions |
| Windows | **Not** supported by current release workflow |

---

## 5. eBPF / XDP — exporter + sample C only (no live loader)

| Artifact | Status |
| :--- | :--- |
| `internal/ebpf/c/xdp_drop.c` | Sample C for **external** build/load |
| `FilterManager.RenderScript()` / `shinkiro kernel` | Emits **text** (commented map updates / nft/iptables scripts) |
| Userspace XDP attach / `BPF_MAP_UPDATE` | **Not implemented** — do not implement in docs PRs |
| SOAR `--apply` | Runs firewall **binaries** (`nft`/`iptables`), not BPF loaders |

---

## 6. Supply chain is Cosign + Syft — not SLSA Level 3

| Artifact | Present |
| :--- | :--- |
| Cosign keyless `sign-blob` on `checksums.txt` → `checksums.bundle` | Yes |
| Syft SPDX + CycloneDX SBOMs on Releases | Yes |
| SLSA Level 3 provenance / generator workflow | **No** — do not claim |

---

## 7. PCAP is on-demand — not continuous mirroring

| Mode | Behavior |
| :--- | :--- |
| Pipeline sink | `MaybeCapture` when `ThreatScore >=` threshold (default 80) |
| TUI `p` | `CaptureNow` (operator-triggered; `operator-` filename prefix) |
| Continuous socket tap of every decoy connection | **Not implemented** |

Env: `SHINKIRO_PCAP_THRESHOLD`, `SHINKIRO_PCAP_DIR` (default `data/pcap`).

---

## 8. Decoy count is fifteen

Exactly **15** protocol decoys in tree and default `config.yaml` `services:`:

SSH, Telnet, MQTT, SMB, Redis, Docker, HTTP, PostgreSQL, Kubernetes, AWS IMDS, MongoDB, Elasticsearch, SMTP, DNS, Modbus.

Do not invent a sixteenth without code.

---

## 9. Correlator v2 is rule-based — not ML

Grouping: same source IP + sliding session window + decoy hop path + explicit grouping reasons. CLI: `shinkiro campaigns`. No neural/ML campaign classifier.

---

## 10. GHCR images are optional

| Condition | Behavior |
| :--- | :--- |
| Default | Local image `shinkiro:local` via `make docker-build` |
| `PUSH_GHCR=true` repository variable | Release job may push `ghcr.io/haiagari/shinkiro:<tag>` (+ `latest`) |
| Unset | **Do not** assume GHCR exists |

---

## 11. Config key is `services:` — not `decoys:`

Runtime YAML (`config.yaml`, Helm files, mode overlays) uses top-level **`services:`**. Older `decoys:` examples are wrong.

---

## 12. Playbook schema is `rules` / `if` / `then`

Real actions today: `block_ip`, `alert` / `notify`, `tag`. Do not document fantasy schemas (`playbooks[].trigger.actions.firewall_drop`, etc.).

---

## 13. Benchmarks — measure, do not invent

No checked-in SLA tables; no `.github/workflows/bench.yml` gate. Run `make bench` and `go test ./tests/chaos`. See [`benchmarks/performance.md`](benchmarks/performance.md).

---

## Quick "do not claim" checklist for PRs

- [ ] No gossip / mesh cluster  
- [ ] No SLSA L3  
- [ ] No live eBPF/XDP loader / `BPF_MAP_UPDATE`  
- [ ] No invented GeoIP coordinates or fake countries  
- [ ] No always-on GeoIP without `.mmdb`  
- [ ] No SOAR live apply without `--apply` / env  
- [ ] No continuous PCAP mirror  
- [ ] No Darwin/Windows prebuilt binaries  
- [ ] No assumed GHCR without `PUSH_GHCR`  
- [ ] No ML correlator  
- [ ] Exactly 15 decoys unless code adds more  
