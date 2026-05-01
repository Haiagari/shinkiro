# 🛡️ OzyRecon Compliance & Risk Mapping

This document maps the current OzyRecon runtime to common security frameworks and operational guardrails. It is not a legal opinion and it is not a substitute for an authorized assessment.

## Scope

OzyRecon is designed for controlled reconnaissance, validation, traceability, and reporting. The engine focuses on:

- relationship-based review
- scoped access control
- evidence-backed output
- operator-visible session traces
- non-blocking lifecycle management

## OWASP Top 10 Mapping

| Category | Risk Name | OzyRecon Capability |
| :--- | :--- | :--- |
| A01:2021 | Broken Access Control | Hashed API keys, scopes, and protected routes with `X-API-KEY` |
| A04:2021 | Insecure Design | Graph-based correlation that exposes cross-target trust relationships |
| A05:2021 | Security Misconfiguration | Policy-approved validation that surfaces common exposure patterns |
| A06:2021 | Vulnerable & Outdated Components | Service fingerprinting before any exploit-like action |
| A07:2021 | Identification & Auth Failures | Multi-key RBAC and access-seed management |
| A09:2021 | Security Logging & Monitoring Failures | Signed evidence and consolidated session traces |

## Evidence and Audit Readiness

OzyRecon is built to help operators collect reviewable evidence for security programs and internal assurance work.

### PCI-DSS

- Requirement 11.3: external testing support through controlled validation
- Requirement 1.2: exposure mapping for network security controls

### SOC 2

- CC7.2: vulnerability management support through continuous validation
- CC7.3: detection and review visibility through signed outputs

### Internal assurance

- session-level traceability
- reproducible findings
- evidence signing for tamper detection
- prioritized graph output for review queues

## Operational Guardrails

- No blind execution
- Gated validation stays explicit
- Sensitive auth checks remain protected
- Blocked paths stay visible in logs and trace output
- Mutable runtime files are bootstrapped locally instead of being committed with secrets

## Practical Note

OzyRecon supports validation and analysis workflows. It should be used only with authorization and within the scope of the engagement or environment being reviewed.
