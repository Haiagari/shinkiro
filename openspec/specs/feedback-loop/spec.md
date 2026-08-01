# Feedback Loop Specification

## Purpose

v1 feedback surface: users report false positives/negatives per decision; reports are stored and surfaced for manual rule adjustment. No auto-retrain in v1.

## Requirements

### Requirement: FEEDBACK-1 — Report endpoint

The proxy MUST expose `POST /v1/feedback` accepting `{decision_id, type: false_positive|false_negative, note?}`.

#### Scenario: Valid report accepted

- GIVEN a decision id from the audit log
- WHEN a valid report is POSTed with a key that has `feedback` scope
- THEN the report is stored and the client receives HTTP 202

### Requirement: FEEDBACK-2 — Report validation

The endpoint MUST reject reports referencing unknown decision ids or invalid types.

#### Scenario: Unknown decision

- GIVEN a decision_id that does not exist in the audit log
- WHEN it is reported
- THEN the endpoint returns HTTP 404 with a machine-readable code

#### Scenario: Invalid type

- GIVEN a type other than `false_positive` or `false_negative`
- WHEN it is reported
- THEN the endpoint returns HTTP 422

### Requirement: FEEDBACK-3 — v1 scope: store and expose

Reports MUST be persisted and MUST be listable via the read endpoint or CLI; the system MUST NOT auto-modify rules in v1.

#### Scenario: Report surfaced, rules untouched

- GIVEN two stored reports
- WHEN they are listed via the read surface
- THEN both appear with timestamps
- AND rule patterns and weights are unchanged automatically

### Requirement: FEEDBACK-4 — Feedback requires auth

The feedback endpoint MUST require a KeyStore key with the `feedback` scope.

#### Scenario: Unauthenticated report

- GIVEN no valid key
- WHEN the endpoint is called
- THEN the proxy returns HTTP 401

### Requirement: FEEDBACK-5 — Feeds manual adjustment

Each report SHOULD reference the rule id when the block was policy-based; surfaced reports MUST be usable to adjust rules, taking effect via the documented policy reload.

#### Scenario: Rule referenced

- GIVEN a false_positive report for a policy block with rule id `r-pii-01`
- WHEN an operator adjusts rule `r-pii-01` and reloads
- THEN the updated rule is active (per POLICY-6)
