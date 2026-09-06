# Campaign Correlator v2

**Package:** `internal/intel/correlator.go`  
**CLI:** `shinkiro campaigns`  
**UI:** TUI Campaigns pane (`Tab`)

Correlator v2 groups honeypot events into adversary **campaigns** using deterministic rules. It is **not** machine learning, clustering heuristics beyond the documented rules, or a TIP-grade attribution engine.

---

## 1. Grouping rules

Events join (or start) a campaign when:

1. **Same source IP** (`RemoteIP`)
2. Within a **sliding session window** (default **2 hours** in CLI rebuild; live correlator uses the engine’s configured window)
3. Optionally across **multiple decoys** — ordered **hop path** (`HopPath`) records service transitions (e.g. `ssh -> redis -> modbus`)

Tracked fields include:

- Technique IDs (from MITRE mapping when present)
- Event / action rolls
- Max threat score, first/last seen
- Explicit **grouping reasons** such as `same_src_ip`, `session_window`, `decoy_hop`

---

## 2. Live vs offline rebuild

| Path | Behavior |
| :--- | :--- |
| `shinkiro up` / `tui` | Pipeline **Correlate** stage calls `Correlator.Ingest` on each scored event |
| `shinkiro campaigns` | Opens JSONL (`--events` or `audit_log_path` / `data/events.jsonl`), rebuilds a fresh correlator with `--window`, prints table/JSON |

```bash
./bin/shinkiro campaigns
./bin/shinkiro campaigns --format json --window 2h --events data/events.jsonl
```

TUI: select Campaigns pane, press `r` to refresh from the live intel store.

---

## 3. Honesty

- Rule-based only — **not ML**
- Hop path ASCII join is intentional (tests assert stable formatting)
- Does not invent MITRE IDs; uses event/`MapToMitre` data already present
- Geo metadata on campaigns comes from event enrichment (optional MaxMind) — empty when GeoIP disabled

See also [`threat-scoring.md`](threat-scoring.md) §3 and [`cli-campaigns-feeds-coverage.md`](../cli-campaigns-feeds-coverage.md).
