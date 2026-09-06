# TUI Operator Actions

The Bubbletea dashboard (`shinkiro tui`) is an **operator loop** over the same in-process decoy mesh, intel store, SOAR BlockApplier, and on-demand PCAP package used by `shinkiro up`.

It is **not** a live mesh topology viewer, eBPF map browser, or continuous packet tap UI.

Help text source of truth: `internal/tui/keys.go`. Broader runbook: [`../operator-guide.md`](../operator-guide.md).

---

## Launch

```bash
# Dry-run SOAR (default) — same guards as `up`
./bin/shinkiro tui

# Live firewall apply for playbook + TUI `b` key
./bin/shinkiro tui --apply
# or: SHINKIRO_SOAR_APPLY=1 ./bin/shinkiro tui

# Optional GeoIP
./bin/shinkiro tui --geoip-db /var/lib/GeoIP/GeoLite2-City.mmdb
```

Wiring (`up.go` → `tui.NewModel`): `EventChan`, active ports, `intel.Engine`, `BlockApplier`, `OnDemandCapture`, `ApplyLive`, `SimulateHost=127.0.0.1`, `MinScore=50` for refresh.

---

## Keybindings

| Key | Action |
| :--- | :--- |
| `↑` / `k`, `↓` / `j` | Move selection in the active list |
| `Tab` | Toggle **Events** ↔ **Campaigns** pane |
| `r` | Refresh high-score events (score ≥ 50) and correlator campaigns from the intel store |
| `b` | SOAR `block_ip` for selected IP — **dry-run by default**; live exec only if started with `--apply` / `SHINKIRO_SOAR_APPLY=1` |
| `p` | Operator on-demand PCAP for selected IP/event (`CaptureNow`, writes under `data/pcap/`) |
| `s` | Run adversary `simulate` suite against `127.0.0.1` (async; mesh listeners already running in-process) |
| `c` | Generate AWS canary honeytoken (HMAC; not live IAM) |
| `?` / `h` | Toggle help overlay |
| `esc` / `x` | Clear status line / close help |
| `q` / `Ctrl+C` | Quit TUI (stops decoy listeners) |

Footer hint when help hidden: `?/h help  ↑↓ select  Tab pane  b block  p pcap  s simulate  c canary  r refresh  x clear  q quit`.

---

## Honesty notes

- **Events pane:** live probes plus optional high-score refresh from `intel.Engine` JSONL.
- **Campaigns pane:** in-memory correlator sessions (`ActiveCampaigns`), sorted by max threat score (v2 hop path / reasons when present).
- **`b` block_ip:** uses `soar.BlockApplier` — dry-run prints nftables/iptables text; does **not** claim silent XDP / BPF map drops.
- **`p` PCAP:** forensic libpcap frames via `internal/pcap`, not continuous socket mirroring.
- **`s` simulate:** real TCP/HTTP probes from `internal/adversary` against local decoy ports.
- **`c` canary:** synthetic AWS key material from `internal/canary` for placement as a honeytoken.

---

## Related

- [Event pipeline / SOAR dry-run / PCAP threshold](event-pipeline.md)
- [CLI reference](../cli-reference.md)
- [Campaign correlator v2](campaign-correlator-v2.md)
