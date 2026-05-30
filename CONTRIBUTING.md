# Contributing

## Standards

- keep changes scoped
- prefer source-of-truth code
- add tests when behavior changes
- keep docs aligned with runtime
- never commit secrets or generated artifacts

## Workflow

```bash
python ozy.py verify
python -m pytest tests/
```

## Docs

If the user-facing flow changes, update the main docs too:

- `README.md`
- `docs/USAGE.md`
- `docs/STATUS.md`
- `docs/RUNTIME_CONTRACT.md`
