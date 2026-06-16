# Code Context

## Files Retrieved

1. `src/discovery/crawler.py` (lines 25-178) - manual host-to-URL normalization, ffuf URL/file construction, no scope filtering.
2. `src/scanners/web/fuzzer.py` (lines 73-140) - same inline normalization and ffuf target construction.
3. `src/validation/policy.py` (lines 18-25, 109-137) - existing `normalize_target_url` and `scope_decision` to reuse.
4. `src/scope/__init__.py` (lines 54-148, 200-274) - reusable scope helpers: `validate_url`, `host_in_allowed_domains`, `filter_assets`, `ScopeGuard`.
5. `src/security/target_validator.py` (lines 29-97) - shared localhost/reserved/DNS-rebinding safety gate.
6. `tests/validation/test_policy.py` (lines 1-103) - normalization and scope decision coverage.
7. `tests/scope/test_scope_guard.py` (lines 1-61) - scope helper coverage.
8. `tests/validation/test_target_validator.py` (lines 1-37) - safety validation coverage.
9. `tests/discovery/test_program_scraper.py` (lines 1-46) - nearby normalization baseline if helper reuse is widened.

## Key Code

- `crawler.py:32-38` does `split()[0]` + `https://` + query/slash stripping inline.
- `crawler.py:48-49, 117-123` derives domains and ffuf filenames from `urlparse(...).netloc`.
- `fuzzer.py:91-117` repeats `split()[0]` + `https://` and builds `ffuf -u {host}/FUZZ` directly.
- `validation/policy.py:18-25` already has `normalize_target_url`.
- `validation/policy.py:109-137` already parses URL and gates via `host_in_allowed_domains` + `is_safe_target`.
- `scope/__init__.py:94-148, 200-274` provides `validate_url`/`filter_assets`/`ScopeGuard` for scope reuse.
- `target_validator.py:29-97` blocks localhost/reserved and DNS-rebound targets.

Likely test updates: `tests/validation/test_policy.py`, `tests/scope/test_scope_guard.py`, `tests/validation/test_target_validator.py`. Add `tests/discovery/test_program_scraper.py` only if normalization helpers are shared into scope ingestion.

## Architecture

`crawler` and `fuzzer` currently own inline normalization. `validation.policy` owns URL normalization and policy decisions; `scope` owns containment/filtering; `target_validator` owns the low-level safety check. The smallest safe cleanup is to centralize host-to-URL normalization and, if the caller has a trusted root domain, route scope filtering through existing helpers instead of ad-hoc checks.

## Start Here

`src/discovery/crawler.py` — it shows the broadest normalization surface and the ffuf path-building pattern to replace first.

## Supervisor coordination

No escalation needed.
