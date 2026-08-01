# Policy Engine Specification

## Purpose

Deterministic, low-latency rules (regex/keywords) evaluated BEFORE the judge LLM; first-match precedence; YAML-defined; reloadable without restart.

## Requirements

### Requirement: POLICY-1 — Rules evaluated before judge

The engine MUST evaluate deterministic rules before any judge call and MUST short-circuit (no judge round-trip) when a rule blocks.

#### Scenario: PII blocked without judge

- GIVEN a prompt containing a PII exfiltration pattern and a matching rule
- WHEN the prompt is evaluated
- THEN the decision is `blocked` with the rule's reason code
- AND the judge is NOT invoked (test asserts zero judge calls)

#### Scenario: No rule match

- GIVEN a prompt matching no rules
- WHEN it is evaluated
- THEN evaluation proceeds to the judge

### Requirement: POLICY-2 — YAML policy files

Policies MUST be defined in YAML files under `config/` (default) and MUST be loaded at startup.

#### Scenario: Rules loaded from YAML

- GIVEN a YAML policy file declaring two rules
- WHEN the engine initializes
- THEN both rules are active and matchable

#### Scenario: Invalid YAML

- GIVEN a malformed policy file
- WHEN loading
- THEN startup fails with a clear error (no partial policy active)

### Requirement: POLICY-3 — Rule schema

Each rule MUST declare: id, kind (`regex`|`keyword`), pattern, action (`block`|`allow`), and a reason code.

#### Scenario: Keyword rule matches

- GIVEN a keyword rule for "ignore previous instructions" with action block
- WHEN a prompt contains that phrase
- THEN the prompt is blocked with the rule's reason code

### Requirement: POLICY-4 — Precedence and first match

Rules MUST be evaluated in declared order; the first matching rule's action MUST win; an `allow` rule preceding a matching `block` rule overrides it.

#### Scenario: First match wins

- GIVEN an allow rule listed before a block rule and both match
- WHEN the prompt is evaluated
- THEN the allow action applies and the request continues

### Requirement: POLICY-5 — Policy sets

Named policy sets MUST be supported; the active set MUST be selected by config and MAY be selected per key scope.

#### Scenario: Default set applied

- GIVEN config selecting the `default` set
- WHEN any proxy request is evaluated
- THEN only rules of the default set apply

### Requirement: POLICY-6 — Reload semantics

Rule changes MUST take effect without process restart via a documented reload (`promptwall rules reload` or SIGHUP); reload MUST be atomic (previous policy stays active until the new one is valid).

#### Scenario: Reload applies new rule

- GIVEN a running proxy and a policy file updated with a new rule
- WHEN `promptwall rules reload` is issued
- THEN subsequent requests match the new rule without restart

#### Scenario: Invalid reload

- GIVEN a reload attempt with an invalid policy file
- WHEN reload is attempted
- THEN the previous policy remains active and an error is reported

### Requirement: POLICY-7 — Block vs allow semantics

A `block` action MUST produce HTTP 403 with `policy_block` plus the rule's reason code; an `allow` action MUST continue to the judge/upstream path.

#### Scenario: Block surfaces to client

- GIVEN a blocked decision
- WHEN the client receives the response
- THEN status is 403 with the rule's reason code
