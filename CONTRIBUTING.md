# Contributing to OzyRecon

Thanks for taking the time to improve OzyRecon. This repository is maintained as a runtime engine plus operational docs, so changes should stay aligned with the current baseline rather than old plan text.

## Standards

- Keep changes scoped and easy to review
- Prefer source-of-truth code over doc guesses
- Add or update tests when behavior changes
- Do not hardcode secrets, domains, IPs, or private keys
- Keep documentation consistent with the actual runtime

## Before You Start

1. Read the runtime docs that match the area you are changing.
2. Check whether the behavior already exists before adding new surface area.
3. Prefer small, isolated patches over broad rewrites.

## Development Flow

```bash
git checkout -b feature/my-change
python ozy.py verify
python -m pytest tests/
```

If the change touches documentation only, still make sure the runtime contract remains accurate.

## Testing Expectations

- Run the relevant targeted tests for the area you touched
- Run the full suite when the change affects runtime, auth, bootstrap, or output contracts
- If a test depends on the local venv or optional libs, document that in the PR description

## Commit Messages

Use conventional commits:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `refactor:` for structural changes without behavior change
- `test:` for test-only updates

## Pull Requests

1. Update `README.md` if the user-facing flow changes.
2. Update the relevant docs under `docs/` if runtime behavior changes.
3. Include verification notes in the PR description.
4. Keep the scope focused on one concern whenever possible.

## Review Notes

- Avoid reintroducing generated artifacts into version control
- Avoid reintroducing secret material into version control
- Keep the engine contract and the documentation in sync
- If a change affects bootstrap, auth, or lifecycle flow, mention that explicitly in the review notes
