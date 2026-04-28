# OzyRecon Bridge Contract

This repo is the engine side of the contract.

## Runtime entrypoint

- Canonical local entrypoint: [`ozy.py`](../ozy.py)
- API runtime: [`src/core/api.py`](../src/core/api.py)
- Normalized export source of truth: [`src/export/normalizer.py`](../src/export/normalizer.py)

## Canonical output shape

The normalized scan export uses [`ScanResult`](../src/export/schema.py) with:

- `session_id`
- `target`
- `mode`
- `assets`
- `services`
- `findings`
- `diff`
- `stats`
- `config`
- `errors`

The frozen runtime envelope and session-trace fields are defined in [`src/core/contracts.py`](../src/core/contracts.py).

## Bridge boundary

The platform-facing adapter is maintained in the Ozy Platform repo, not in this tree.
That means this repo can define and validate the contract, but adapter code changes
must be applied where the platform bridge actually lives.

## Compatibility closure

This tree freezes the local contract fields and verifies them through tests.
The remaining compatibility work in the platform repo should consume the same field set without inventing a different runtime shape.

## Legacy export helpers

The raw artifact exporter was removed from this tree. New code should use the
normalized exporter and the platform-specific exporters from this package.
