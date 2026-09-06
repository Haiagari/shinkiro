# ThreatFox & AbuseIPDB CLI

**Package:** `internal/intel/feeds.go`  
**Commands:** `shinkiro threatfox`, `shinkiro abuseipdb`

## Keys

| Feed | Env var | Header | Obtain |
| :--- | :--- | :--- | :--- |
| ThreatFox (abuse.ch) | `THREATFOX_API_KEY` | `Auth-Key` | Free Auth-Key at https://auth.abuse.ch/ |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | `Key` | https://www.abuseipdb.com/account/api |

If the key is missing, the CLI exits non-zero with a clear message naming the env var. No placeholder / fake IoC data is emitted.

## ThreatFox

```bash
export THREATFOX_API_KEY=…
shinkiro threatfox --search 198.51.100.10
shinkiro threatfox --days 1 --format json
```

Uses `POST https://threatfox-api.abuse.ch/api/v1/` with `query=search_ioc` or `query=get_iocs`.

The older helper `GenerateThreatFoxFeed` still exports honeypot events into ThreatFox-oriented JSON for offline sharing — it does not call the network.

## AbuseIPDB

```bash
export ABUSEIPDB_API_KEY=…
shinkiro abuseipdb --ip 198.51.100.10
shinkiro abuseipdb --ip 198.51.100.10 --max-age 30 --format json
```

Uses `GET https://api.abuseipdb.com/api/v2/check`.

## Tests

Unit tests use `net/http/httptest` (`feeds_test.go`) — no live network required in CI.
