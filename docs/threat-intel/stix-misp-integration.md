# STIX 2.1 & MISP Threat Intelligence Integration Guide

Shinkiro is engineered to function as an autonomous edge sensor producing high-fidelity, structured Cyber Threat Intelligence (CTI).

## STIX 2.1 Objects Generated

Every adversary interaction with a threat score >= 60 triggers the generation of STIX 2.1 Indicator objects:

```json
{
  "type": "indicator",
  "id": "indicator--ssh-login-1757038920192837",
  "spec_version": "2.1",
  "created": "2026-09-04T20:30:00Z",
  "modified": "2026-09-04T20:30:00Z",
  "name": "Malicious Honeypot Probe from 198.51.100.88",
  "description": "Observed ssh probe on decoy port 2222 (SSH_BRUTE_FORCE). Threat score: 90",
  "pattern": "[ipv4-addr:value = '198.51.100.88']",
  "pattern_type": "stix",
  "valid_from": "2026-09-04T20:30:00Z",
  "confidence": 90,
  "labels": [
    "malicious-activity",
    "honeypot",
    "attacker-ip"
  ]
}
```

## Integrating with SIEM / OpenCTI / MISP

### 1. Direct Pipeline Export
You can stream output directly into OpenCTI or MISP via cron or pipeline:

```bash
shinkiro stix | curl -X POST https://misp.internal/events/add \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  -d @-
```

### 2. Live Cluster Hub Ingestion
For multi-cloud enterprise deployments, point sensors to the central Shinkiro Hub (`shinkiro cluster hub --port 9090`).
