# Event Pipeline, SOAR block_ip, and On-Demand PCAP

This note describes the unified telemetry path landed for roadmap items covering pipeline / SOAR / PCAP (and extended by GeoIP + correlator v2).

Related: [`operator-guide.md`](../operator-guide.md) · [`cli-reference.md`](../cli-reference.md) · [`system-architecture.md`](system-architecture.md)

---

## Pipeline stages

`internal/pipeline` is a small in-process bus. Decys still emit on `chan intel.Event` via the multiplexer; `shinkiro up` / `tui` feed that channel into `Bus.RunChannel`.

Ordered stages (`cmd/shinkiro/up.go`):

1. **Score** — ensure MITRE mapping (`intel.MapToMitre`) and **optional** MaxMind GeoLite2 metadata enrichment (`SHINKIRO_GEOLITE2_PATH` / `--geoip-db`; no-op when unset).
2. **Correlate** — `intel.Correlator.Ingest` for multi-decoy campaigns (v2 rules — same IP, window, hop path).
3. **Playbook** — `soar.Engine.Process` (YAML rules from `playbooks.yaml`).
4. **Sink** — Prometheus metrics, critical webhook, on-demand PCAP, `intel.Engine.Persist` (JSONL), TUI fan-out / console log.

Threat scores themselves are still assigned by decoy handlers when they emit events; the Score stage enriches rather than inventing a parallel scorer.

```text
decoy Emit → events chan → Bus.RunChannel
                              │
                    StageScore (MITRE + GeoIP)
                              │
                    StageCorrelate (campaigns)
                              │
                    StagePlaybook (SOAR)
                              │
                    StageSink (metrics, PCAP, Persist, UI)
```

---

## SOAR `block_ip`: dry-run vs apply

`internal/soar.BlockApplier` generates real `nftables` / `iptables` command text via `internal/defense.GenerateRules`.

| Mode | How to enable | Behaviour |
| :--- | :--- | :--- |
| **Dry-run (default)** | nothing | Prints would-be firewall commands; does **not** exec `iptables`/`nft`; does **not** POST webhooks |
| **Live apply** | `shinkiro up --apply` / `tui --apply` **or** `SHINKIRO_SOAR_APPLY=1` | Executes generated firewall commands and optionally POSTs JSON to `SHINKIRO_SOAR_BLOCK_WEBHOOK` |

Additional env:

- `SHINKIRO_SOAR_BLOCK_FORMAT` — `nftables` (default), `iptables`, or `cidr`
- `SHINKIRO_SOAR_BLOCK_WEBHOOK` — optional URL for live apply JSON POST

**Honesty:** live apply runs explicit shell firewall binaries (or a webhook). It does **not** attach XDP, update BPF maps, or silently “auto-block in kernel.”

Example dry-run output includes lines such as:

```text
[SOAR block_ip dry-run] dry-run: would block 192.0.2.50 via iptables ...
iptables -A INPUT -s 192.0.2.50 -j DROP
```

Playbook schema reminder (`playbooks.yaml`):

```yaml
rules:
  - name: example
    enabled: true
    if:
      decoy: ssh
      min_score: 75
      action_match: LOGIN
    then:
      - type: block_ip
      - type: alert
```

---

## On-demand PCAP (high score)

When `ThreatScore >=` threshold (default **80**), the sink stage calls `pcap.OnDemandCapture.MaybeCapture`, which opens a libpcap 2.4 file under `data/pcap/` (configurable) and writes a forensic frame (JSON event metadata as the packet payload using the existing `internal/pcap` writer).

| Env | Default | Meaning |
| :--- | :--- | :--- |
| `SHINKIRO_PCAP_THRESHOLD` | `80` | Score gate |
| `SHINKIRO_PCAP_DIR` | `data/pcap` | Output directory |

TUI key `p` calls `CaptureNow` (operator path; filename prefix `operator-`) and does not require the score gate.

This is **on-demand / threshold-gated**, not continuous packet mirroring of every decoy socket.

```bash
shinkiro up
# after a high-score probe:
ls data/pcap/
# highscore-<ip>-<unix>.pcap
```

---

## Optional GeoIP

See [`docs/threat-intel/geolite2-geoip.md`](../threat-intel/geolite2-geoip.md). When disabled, Score still maps MITRE; `geo_*` metadata keys are simply absent.
