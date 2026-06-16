# Contributing

## Standards

- Keep changes scoped to a single concern
- Prefer source-of-truth code over comments
- Add tests when behavior changes
- Keep docs aligned with runtime
- Never commit secrets or generated artifacts
- Follow conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`

## Workflow

```bash
python ozy.py doctor          # validate environment
python -m pytest tests/       # run tests
ruff check src/ tests/        # lint
```

## Docs

If the user-facing flow changes, update:

- `README.md` — main project documentation
- `docs/PLATFORM.md` — API and bridge contracts
