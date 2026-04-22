# OzyRecon v5.0 Operational Modes

## Overview

OzyRecon v5.0 introduces **Assisted Validation** across all operational intents, transforming technical output into verified, decision-grade intelligence.

---

## ⚡ HUNT Mode (Base Intelligence)

**Objective**: Establish an intelligent baseline and generate attack hypotheses for manual validation.

### Usage
```bash
ozy hunt -t target.com
```

### v5.0 Workflow
1. **Asset Discovery**: Full enumeration of subdomains and assets.
2. **Intelligence Correlation**: Cross-referencing ports, services, and tech stack.
3. **Hypothesis Generation**: The system proposes attack vectors based on correlation.
4. **Human Gate**: Hypotheses are held in `PENDING_APPROVAL` status awaiting human action (`ozy gate`).
5. **Assisted Validation**: Only approved hypotheses are validated by the orchestrator (`ozy validate`).

### Use Cases
- New targets with no prior history.
- Audits requiring full control over the technical noise generated.
- Assisted Red Teaming scenarios.

---

## ◎ CONTINUOUS Mode (Drift Detection)

**Objective**: 24/7 monitoring with change detection and low-risk auto-validation.

### Usage
```bash
ozy continuous -t target.com
```

### v5.0 Workflow
1. Periodic differential scanning.
2. Detection of new assets or service drift.
3. Auto-validation of low-risk hypotheses (e.g., version disclosure).
4. Escalation to the Human Gate for critical infrastructure changes.

---

## Summary of Capabilities v5.0

| Mode | Primary Goal | Validation Type | User Control |
|------|--------------|-----------------|--------------|
| **HUNT** | Base Intelligence | Manual (Gate) | Total |
| **CONTINUOUS** | Drift & Delta | Hybrid | Balanced |
| **RESEARCH** | CVE Verification | Direct | Surgical |
| **CAMPAIGN** | Pattern Scaling | Rule-based | Centralized |
| **SERVICE** | Reporting | Evidence-based | Audit-focused |
