# Campaigns, ThreatFox / AbuseIPDB & ATT&CK Coverage CLI

Companion to the full [`cli-reference.md`](cli-reference.md). Packages: `internal/intel` (correlator, feeds, coverage helpers).

---

## Campaigns (correlator v2)

```bash
./bin/shinkiro campaigns
./bin/shinkiro campaigns --format json --window 2h --events data/events.jsonl
```

| Flag | Default | Meaning |
| :--- | :--- | :--- |
| `--format` | `table` | `table` or `json` |
| `--events` | `audit_log_path` or `data/events.jsonl` | JSONL input |
| `--window` | `2h` | Session window for rebuild |

Rule-based grouping: same source IP + sliding session window + decoy hop path (**not ML**). See [`architecture/campaign-correlator-v2.md`](architecture/campaign-correlator-v2.md).

---

## ThreatFox

Requires `THREATFOX_API_KEY` (Auth-Key from https://auth.abuse.ch/).

```bash
export THREATFOX_API_KEY=...
./bin/shinkiro threatfox --search 198.51.100.10
./bin/shinkiro threatfox --days 1 --format json
```

Missing key or missing `--search`/`--days` exits non-zero with a clear error. No fake IoCs. Details: [`threat-intel/threatfox-abuseipdb.md`](threat-intel/threatfox-abuseipdb.md).

---

## AbuseIPDB

Requires `ABUSEIPDB_API_KEY`.

```bash
export ABUSEIPDB_API_KEY=...
./bin/shinkiro abuseipdb --ip 198.51.100.10
./bin/shinkiro abuseipdb --ip 198.51.100.10 --max-age 30 --format json
```

---

## ATT&CK coverage

Maps documented decoy-matrix technique tags (optional `--runtime-mapper` for `MapToMitre`). Does not invent ATT&CK IDs.

```bash
./bin/shinkiro coverage
./bin/shinkiro coverage --format json --runtime-mapper
# alias: shinkiro attack-coverage
```
