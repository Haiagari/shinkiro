# Cyber Threat Intelligence (CTI) & SIEM Integration

**Product:** Shinkiro (蜃気楼)  
**Formats:** STIX 2.1, ArcSight CEF, RFC5424 Syslog, Elastic Common Schema (ECS v8.x), ThreatFox-oriented offline helpers, AbuseIPDB/ThreatFox live CLIs

Docs hub: [`../README.md`](../README.md) · Feeds: [`threatfox-abuseipdb.md`](threatfox-abuseipdb.md) · GeoIP: [`geolite2-geoip.md`](geolite2-geoip.md)

---

## 1. Overview

Shinkiro transforms honeynet interactions into structured CTI/SIEM feeds without proprietary agents.

Every interaction across the **15** decoys can receive:

- **Cryptographic hashing** of scripts/commands where decoys implement it
- **Optional MaxMind GeoLite2** enrichment (`SHINKIRO_GEOLITE2_PATH` / `--geoip-db`) — no-op when unset; **never invents coordinates**
- **MITRE ATT&CK mapping** via `MapToMitre` / decoy tags
- **Campaign correlation v2** (rule-based — not ML)
- **Threat score 0–100** assigned by decoy handlers (pipeline Score stage enriches; it does not invent a parallel scorer)

---

## 2. Supported exporters

| CLI | Format | Notes |
| :--- | :--- | :--- |
| `shinkiro stix` | STIX 2.1 JSON bundle | From `data/events.jsonl`; empty bundle if missing |
| `shinkiro cef` | ArcSight CEF | Recent events (500) via config `node_name` |
| `shinkiro syslog` | RFC5424 | Wraps telemetry for rsyslog / SIEM |
| `shinkiro ecs` | ECS v8.x JSON | Batch JSON for Elastic/OpenSearch |
| `shinkiro threatfox` | Live HTTP API | Needs `THREATFOX_API_KEY` |
| `shinkiro abuseipdb` | Live HTTP API | Needs `ABUSEIPDB_API_KEY` |

```bash
./bin/shinkiro stix > /tmp/shinkiro-threats.json
./bin/shinkiro cef
./bin/shinkiro syslog | nc -u -w1 10.0.0.50 514
./bin/shinkiro ecs > /tmp/shinkiro-ecs.json
```

---

## 3. STIX 2.1

`internal/intel/stix` builds OASIS STIX 2.1 bundles. High-score events become `indicator` objects with IPv4 patterns and MITRE labels when present.

```bash
./bin/shinkiro stix > /tmp/shinkiro-threats.json
```

Example push to MISP / OpenCTI (operator-owned auth):

```bash
./bin/shinkiro stix | curl -s -X POST https://misp.example/events/add \
  -H "Authorization: $MISP_AUTH_KEY" \
  -H "Content-Type: application/json" \
  -d @-
```

---

## 4. CEF & Syslog

```bash
./bin/shinkiro cef
./bin/shinkiro syslog
```

CEF fields include source IP, ports, decoy app, action, MITRE IDs, and threat score when available. Syslog wraps CEF-oriented payloads in RFC5424 frames (facility/severity as implemented in `internal/intel/siem`).

---

## 5. Elastic Common Schema (ECS)

```bash
./bin/shinkiro ecs > /tmp/shinkiro-ecs.json
```

Maps recent events into ECS-oriented JSON (`ecs` package). Geo fields appear only when MaxMind enrichment populated metadata — do not expect invented city/country without a DB.

Example Logstash pattern (operator-owned):

```ruby
input {
  exec {
    command => "/usr/local/bin/shinkiro ecs"
    interval => 60
    codec => "json"
  }
}
```

---

## 6. Community feeds vs offline helpers

- **Live CLIs** (`threatfox`, `abuseipdb`) call real HTTP APIs with your keys.
- **Offline** `GenerateThreatFoxFeed`-style helpers export honeypot-derived IoC JSON for sharing — they do not POST to abuse.ch by themselves.

---

## 7. Splunk / JSONL

Monitor the audit log directly:

```ini
[monitor:///path/to/data/events.jsonl]
sourcetype = _json
index = honeypot_intel
```

Path comes from `audit_log_path` in `config.yaml` (default `data/events.jsonl`).
