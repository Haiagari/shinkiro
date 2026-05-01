# 📖 OzyRecon: Use Cases & Operational Scenarios

OzyRecon v7.5 is a **controlled reconnaissance and review engine**.
 This document describes practical scenarios for discovery, correlation, evidence collection, and safe validation.

---

## 1. Controlled Discovery Under Defensive Controls
When a target has aggressive rate limiting or filtering, use OzyRecon to keep the workflow explicit and reviewable.
*   **Activity**: Run the engine with the approved validation policy and observe the normalized output.
*   **Outcome**: Maintain controlled discovery without bypass-oriented language or hidden execution paths.

## 2. Cross-Asset Correlation
Logic and exposure patterns often span multiple assets that automated scanners see as isolated.
*   **Activity**: Correlate findings across subdomains, ports, and historical scans.
*   **Outcome**: Surface review priorities and relationships that are useful for remediation.

## 3. Evidence-Based Validation
Reduce false positives by validating only the findings allowed by policy.
*   **Activity**: Let gated validators confirm exposure or report evidence for review.
*   **Outcome**: A final report with reproducible proofs and traceable evidence.

## 4. Continuous Surface Monitoring
Maintain a live, relationship-based map of your infrastructure.
*   **Activity**: Run continuous discovery against approved targets and keep the session trace for audit.
*   **Outcome**: Detect new exposures or configuration drift before they create operational risk.

---

## 🛠️ Specialized v7.5 Pillars:

### A. Controlled Request Identity
Every request can use a consistent identity profile so repeated runs stay comparable and auditable.

### B. Graph-Derived Hypotheses
The engine doesn't just scan ports; it generates review hypotheses based on the **Knowledge Graph**'s relationship data.

### C. Cryptographically Signed Evidence
All findings in the evidence layer are digitally signed with Ed25519, providing an immutable audit trail for review and compliance.

---
*For more technical details, see the [Architecture Guide](architecture.md).*
