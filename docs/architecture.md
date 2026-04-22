# OzyRecon v5.7 Architecture — Assisted Offensive Validation

## Overview

OzyRecon v5.7 is a **Security Validation Platform** designed to transform offensive reconnaissance into auditable, high-confidence intelligence.

## The 14 Pillars of OzyRecon

### 1-8. Core Discovery Layer (Legacy)
High-performance discovery engine including Asset Enumeration, Service Fingerprinting, and Stealth Protection (OPSEC).

### 9. Human Gate
Critical decision points where the system proposes hypotheses and the operator authorizes execution.

### 10. Validation Layer
Surgical probe execution engine. Focuses on confirmation rather than exploitation.
- `web.py`, `http.py`, `cms.py`, `auth.py`: Specialized validators.

### 11. Evidence Engine
Integrity-aware data vault. SHA256-signed proof.

### 12. Workflow State Machine
Manages the complete lifecycle of technical signals.

### 13. Knowledge Graph Representation (New v5.7)
Correlation of all attack surface entities (Target -> Subdomain -> Port -> Hypothesis) into a unified visual graph using Cytoscape.js.

### 14. Visual Evidence Engine (New v5.7)
Automated visual proof capture using Playwright for confirmed HTTP findings.

---

## Technical Flow: Visual Evidence (v5.7)

1.  **Detection**: `HTTPValidator` confirms a sensitive finding (e.g., exposed .env).
2.  **Trigger**: If status is `confirmed`, the validator calls `src.utils.visual.capture_screenshot()`.
3.  **Headless Execution**: Playwright launches a headless Chromium instance, navigates to the target URL, and renders the page.
4.  **Capture**: A high-resolution PNG is saved in `runtime/evidence/screenshots/`.
5.  **Integrity**: The path is returned to the validator, which adds it to the evidence list.
6.  **Persistence**: `EvidenceEngine` records the path and calculates a SHA256 of the image file (metadata).

---

## Data Flow Pipeline

```
Target → Discovery → Intelligence (Correlation)
                     ↓
             [HYPOTHESIS GENERATED]
                     ↓
               [HUMAN GATE] <─── Operator Authorization
                     ↓
             [VALIDATION LAYER] ───> Surgical Probes & Auth Spraying
                     ↓
              [VISUAL EVIDENCE] ───> Automated Screenshots
                     ↓
              [EVIDENCE ENGINE] ───> Secure Evidence Vault
                     ↓
               [REPORT ENGINE] ───> Executive Narrative (MD/JSON)
```


## Project Status
**Phase 2: Assisted Validation — COMPLETED ✅**
**Classification**: Professional Security Validation Platform for AppSec Teams.
