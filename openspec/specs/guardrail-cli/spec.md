# Guardrail CLI Specification

## Purpose

`promptwall` Click+Rich CLI over the kept shell (`cli/ozy.py` + `cli/shared.py` minus mode loader): serve, rules, keys, audit, self-test. Renames the entry point `ozy` → `promptwall`.

## Requirements

### Requirement: CLI-1 — Entry point rename

The console script MUST be renamed from `ozy` to `promptwall`; `promptwall --help` MUST list all commands; the old `ozy` entry point MUST be removed.

#### Scenario: New entry point works

- GIVEN an installed package
- WHEN `promptwall --help` runs
- THEN it exits 0 and lists serve/rules/keys/audit/self-test

#### Scenario: Old entry removed

- GIVEN an installed package after rename
- WHEN `ozy --help` runs
- THEN it fails with command not found

### Requirement: CLI-2 — serve command

`promptwall serve` MUST start the proxy (FastAPI/uvicorn) using config.

#### Scenario: Serve starts

- GIVEN valid config
- WHEN `promptwall serve --port 8080` runs
- THEN the proxy listens on 8080 and `/health` responds

### Requirement: CLI-3 — rules command

`promptwall rules` MUST list rules and `promptwall rules reload` MUST reload YAML policies (per POLICY-6).

#### Scenario: Rules listed

- GIVEN loaded policy files
- WHEN `promptwall rules list` runs
- THEN each rule id, kind, and action is printed

### Requirement: CLI-4 — keys command

`promptwall keys` MUST create, list, and revoke KeyStore keys with scopes and rate limits; the plaintext key MUST be returned exactly once at creation.

#### Scenario: Key created

- GIVEN `promptwall keys create --name app-a --scope chat --rate-limit 100`
- WHEN it runs
- THEN a `promptwall_*` plaintext key is printed once and only its hash is stored

### Requirement: CLI-5 — audit command

`promptwall audit` MUST read audit entries and verify Ed25519 signatures, reporting any tampered entries.

#### Scenario: Signatures verified

- GIVEN an audit log with signed entries
- WHEN `promptwall audit` runs
- THEN it reports the entry count and all signatures valid

#### Scenario: Tampered entry flagged

- GIVEN one tampered audit entry
- WHEN `promptwall audit` runs
- THEN that entry is flagged as invalid

### Requirement: CLI-6 — self-test command

`promptwall self-test` MUST run built-in checks (signing roundtrip, policy load, config validity, health) and exit non-zero on failure.

#### Scenario: All checks pass

- GIVEN a healthy installation
- WHEN `promptwall self-test` runs
- THEN it exits 0 with per-check results

#### Scenario: Failing check

- GIVEN an invalid policy file or missing judge config
- WHEN `promptwall self-test` runs
- THEN it exits non-zero and names the failing check
