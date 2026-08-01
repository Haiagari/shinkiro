# Guardrail Audit Specification

## Purpose

Tamper-evident audit trail: every decision signed with Ed25519 via EvidenceSigner (from `src/utils/crypto.py`), JSONL retention with 50MB rotation, read endpoints and verification.

## Requirements

### Requirement: AUDIT-1 — Signed decisions

Every guardrail decision MUST be recorded as an audit entry signed with Ed25519 via EvidenceSigner over canonical JSON; the signature MUST verify against the public key.

#### Scenario: Entry signed and verified

- GIVEN a completed decision
- WHEN the entry is written
- THEN it contains a base64 Ed25519 signature
- AND verifying the entry with the public key succeeds

### Requirement: AUDIT-2 — Signed payload scope

The signed payload MUST contain decision + metadata (timestamp, key name, reason code, outcome, prompt hash) and MUST NOT contain full prompt content (privacy default).

#### Scenario: No prompt content

- GIVEN a blocked prompt with sensitive content
- WHEN the audit entry is written
- THEN the entry contains a prompt hash but not the prompt text

### Requirement: AUDIT-3 — JSONL retention and rotation

Audit entries MUST be appended as JSONL via AuditLogger with automatic rotation at 50MB keeping 5 backups.

#### Scenario: Rotation at size

- GIVEN a log file at the 50MB threshold
- WHEN the next entry is appended
- THEN the log rotates and a new file is started

### Requirement: AUDIT-4 — Verification

The system MUST expose signature verification; a tampered entry MUST fail verification.

#### Scenario: Tamper detected

- GIVEN an audit entry whose fields were modified after signing
- WHEN it is verified
- THEN verification returns false

### Requirement: AUDIT-5 — Read endpoints

The proxy MUST expose audit read endpoints (`GET /v1/audit`) with pagination, restricted to keys with the `audit` scope; `promptwall audit` MUST verify signatures.

#### Scenario: Read with audit scope

- GIVEN a key with `audit` scope
- WHEN `GET /v1/audit` is requested
- THEN paginated entries are returned

#### Scenario: Read without scope

- GIVEN a key without `audit` scope
- WHEN the endpoint is requested
- THEN the proxy returns HTTP 403
