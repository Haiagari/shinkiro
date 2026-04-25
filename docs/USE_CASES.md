# 📖 OzyRecon: Use Cases & Operational Scenarios

OzyRecon v6.0 (Phantom Blade) is an **Advanced Persistent Reconnaissance Platform**. This document describes how to leverage its stealth and logic engines in professional scenarios.

---

## 1. APT-Grade Stealth Operations (Red Team)
In engagements against mature organizations with advanced WAFs (Cloudflare, Akamai), traditional tools are blocked instantly.
*   **Activity**: Use OzyRecon's **Chameleon Engine** to impersonate legitimate browser fingerprints (JA3/TLS).
*   **Outcome**: Perform deep discovery and fuzzing without triggering IP-based bans or bot-detection alarms.

## 2. Cross-Asset Logic Discovery (Zero-Day Hunting)
Logic bugs often span multiple assets that automated scanners see as isolated.
*   **Activity**: Run the **Logic Brain** to correlate findings. For example, connecting a session cookie leak on a `dev` subdomain with an unauthenticated API on the `prod` infrastructure.
*   **Outcome**: Discovery of complex "Trust Chains" and logical attack paths that standard tools cannot visualize.

## 3. Surgical Evidence Validation (Zero-Noise Pentesting)
Stop wasting time filtering false positives. 
*   **Activity**: Utilize the **Surgical Prober** to automatically confirm findings. If Ozy detects a potential `.env` exposure, it launches a 50-byte probe to verify secrets without exfiltrating data or making noise.
*   **Outcome**: A final report with **100% Confirmed Proofs**, ready for immediate remediation.

## 4. Continuous Attack Surface Monitoring (EASM)
Maintain a live, relationship-based map of your infrastructure.
*   **Activity**: Deploy OzyRecon in **Autopilot Mode**. Let the engine auto-approve and validate high-confidence (0.95+) findings.
*   **Outcome**: Detection and immediate validation of "Shadow IT" or accidental exposures before they are exploited.

---

## 🛠️ Specialized v6.0 Pillars:

### A. Synthetic Identity Generation
Every request is backed by a consistent, synthetic identity (User-Agent + Client Hints + TLS Profile), making OzyRecon indistinguishable from a real user.

### B. Brain-Derived Hypotheses
The engine doesn't just scan ports; it generates attack hypotheses based on the **Knowledge Graph**'s relationship data.

### C. Cryptographically Signed Evidence
All findings in the **Evidence Vault** are signed with SHA256, providing an immutable audit trail for legal and compliance requirements.

---
*For more technical details, see the [Architecture Guide](architecture.md).*
