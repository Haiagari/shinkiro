# Campaigns, ThreatFox / AbuseIPDB & ATT&CK Coverage CLI

## Campaigns (correlator v2)

```bash
./bin/shinkiro campaigns
./bin/shinkiro campaigns --format json --window 2h --events data/events.jsonl
```

Rule-based grouping: same source IP + sliding session window + decoy hop path (**not ML**). See `docs/architecture/campaign-correlator-v2.md`.

## ThreatFox

Requires `THREATFOX_API_KEY` (Auth-Key from https://auth.abuse.ch/).

```bash
export THREATFOX_API_KEY=...
./bin/shinkiro threatfox --search 198.51.100.10
./bin/shinkiro threatfox --days 1 --format json
```

## AbuseIPDB

Requires `ABUSEIPDB_API_KEY`.

```bash
export ABUSEIPDB_API_KEY=...
./bin/shinkiro abuseipdb --ip 198.51.100.10
./bin/shinkiro abuseipdb --ip 198.51.100.10 --max-age 30 --format json
```

Missing keys exit non-zero with a clear error (no fake results). Details: `docs/threat-intel/threatfox-abuseipdb.md`.

## ATT&CK coverage

Maps documented decoy-matrix technique tags (optional `--runtime-mapper` for `MapToMitre`).

```bash
./bin/shinkiro coverage
./bin/shinkiro coverage --format json --runtime-mapper
# alias: shinkiro attack-coverage
```
