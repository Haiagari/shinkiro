# Usage

OzyRecon runs as a staged, scoped workflow.

## Standard flow

1. `python ozy.py init`
2. `python ozy.py doctor`
3. `python ozy.py flow <target> --profile safe-active`
4. `python ozy.py diff <target>`

## Scope management

- `python ozy.py scope list --json`
- `python ozy.py scope add example.com *.example.com`
- `python ozy.py scope remove example.com *.example.com`
- `python ozy.py scope import targets.txt`

## Profiles

| Profile | Purpose |
|---|---|
| `passive` | Public-source discovery only |
| `safe-active` | Low-impact validation |
| `authorized` | Full authorized runtime |

## What `flow` does

- preflight verification
- scope and authorization checks
- adaptive discovery and scoring
- analysis snapshot generation
- report generation
- diff comparison against prior sessions

## Artifacts

- `runs/<session_id>/analysis.md`
- `runs/<session_id>/analysis.json`
- `runs/<session_id>/collaboration.json`
- `reports/reales/...`

## API notes

- session trace is exposed for every run
- `GET /health`
- `POST /hunt`
- `GET /sessions/{session_id}/trace`
- `GET /sessions/{session_id}/analyze`

## Quiet mode

Use `--json` when you need machine-readable output. Human-oriented panels are suppressed in that mode.
