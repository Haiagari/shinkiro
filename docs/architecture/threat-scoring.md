# Threat Scoring, Campaign Correlation & IoC Attribution Engine

**Product:** Shinkiro (蜃気楼)  
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

See remaining sections in this file for scoring matrix, correlator v2, firewall export honesty, SOAR playbook schema (`rules`/`if`/`then`), and optional MaxMind GeoIP notes (never invents coordinates).

```bash
./bin/shinkiro campaigns --format json --window 2h
./bin/shinkiro export --format nftables --threshold 80
./bin/shinkiro kernel   # sample script text only
```

**Dry-run default** for `block_ip`; live only with `--apply` / `SHINKIRO_SOAR_APPLY=1`. Details: [`event-pipeline.md`](event-pipeline.md).
