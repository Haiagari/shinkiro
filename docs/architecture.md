# OzyRecon v5.0 Architecture — Assisted Offensive Validation

## Overview

OzyRecon v5.0 is a **Security Validation Platform** designed to transform offensive reconnaissance into auditable, high-confidence intelligence. It moves beyond simple wrappers by implementing a stateful, decision-aware architecture aligned with modern DevSecOps standards.

## Key Differentiation: Platform vs. Scanner

| Feature | Traditional Scanner | OzyRecon (Platform) |
|---------|---------------------|----------------------|
| Approach | Automated discovery | Assisted Validation |
| Output | Unverified noise | Evidence-backed findings |
| Logic | Fixed pipeline | Adaptive State Machine |
| Control | None (Autopwn style)| Human Gate (Authorized) |
| Audit | Fragmented logs | Integrity-hashed Evidence |

## The 12 Pillars of OzyRecon

### 1-8. Core Discovery Layer (Legacy)
High-performance discovery engine including Asset Enumeration, Service Fingerprinting, and Stealth Protection (OPSEC).

### 9. Human Gate (New)
Critical decision points where the system proposes hypotheses and the operator authorizes execution.
- `ozy gate list`: Hypothesis review.
- `ozy gate approve`: Action authorization.

### 10. Validation Layer (New)
Surgical probe execution engine. Focuses on confirmation rather than exploitation.
- `web.py`, `http.py`, `cms.py`: Specialized validators for different signal types.

### 11. Evidence Engine (New)
Integrity-aware data vault.
- Stores raw metadata, headers, and responses.
- Generates SHA256 hashes to ensure chain of custody for every finding.

### 12. Workflow State Machine (New)
Manages the complete lifecycle of technical signals:
`DISCOVERED` → `ANALYZED` → `HYPOTHESIZED` → `PENDING_APPROVAL` → `APPROVED` → `VALIDATING` → `VALIDATED` → `REPORTED`.

---

## Data Flow Pipeline

```
Target → Discovery → Intelligence (Correlation)
                     ↓
             [HYPOTHESIS GENERATED]
                     ↓
               [HUMAN GATE] <─── Operator Authorization
                     ↓
            [VALIDATION LAYER] ───> Surgical Probes
                     ↓
             [EVIDENCE ENGINE] ───> Secure Evidence Vault
                     ↓
              [REPORT ENGINE] ───> Executive Narrative (MD/JSON)
```

## Project Status
**Phase 2: Assisted Validation — COMPLETED ✅**
**Classification**: Professional Security Validation Platform for AppSec Teams.
