# Contributing to Shinkiro (蜃気楼)

Thank you for your interest in contributing to **Shinkiro**! We welcome bug reports, protocol decoy pull requests, documentation improvements, performance measurements, and security hardening.

Read first:

- [`AGENTS.md`](AGENTS.md) — product truth for agents/contributors  
- [`docs/honesty-limitations.md`](docs/honesty-limitations.md) — what not to claim or implement casually  
- [`docs/development.md`](docs/development.md) — make targets, e2e, fuzz  

---

## How to Contribute

1. Fork the repository and create your feature branch: `git checkout -b feat/my-new-decoy`.
2. Ensure that code complies with Go 1.24+ conventions and formatting (`go fmt ./...`).
3. Run the full test suite with race detector enabled:
   ```bash
   go test -v -race ./...
   # or: make test
   ```
4. For decoy / parser changes, also run relevant fuzz targets and e2e when practical:
   ```bash
   make fuzz
   make e2e
   ```
5. Optional local microbenchmarks (not CI-gated):
   ```bash
   make bench
   ```
6. Follow Conventional Commits format (`feat:`, `fix:`, `docs:`, `perf:`). Do **not** add AI attribution trailers or `Co-Authored-By` lines.
7. Update docs when behavior changes — English, thorough, no stubs. Link new pages from [`docs/README.md`](docs/README.md). Keep [`CHANGELOG.md`](CHANGELOG.md) Unreleased accurate (do not invent old version entries).
8. Open a Pull Request on GitHub. Do **not** merge from agent automation unless a human explicitly requests it. Do **not** create release tags unless asked.

---

## Security Architecture Principles

- **Fail-Closed**: Any unhandled error or malformed payload must drop or close safely without panicking.
- **Zero Host Mutation**: Decoys must execute strictly in memory. Never write adversary binaries to disk or execute real host shells.
- **Zero-Footprint**: Use goroutine sandboxes and timeouts to prevent Slowloris resource exhaustion.
- **Honest defense claims**: SOAR `block_ip` is dry-run by default; live apply needs `--apply` / `SHINKIRO_SOAR_APPLY=1`. eBPF package is a **text exporter** + sample C — do not implement a live loader unless a dedicated roadmap item lands.
- **Config / playbooks**: Use `services:` and `rules`/`if`/`then` — never revive deprecated `decoys:` or fantasy playbook schemas in examples.

---

## Documentation PRs

Prefer structured blocks (getting started, architecture, operator, threat intel, deploy, CLI, development, honesty). Match flags/env vars to `cmd/shinkiro` and package source. Cross-link the docs hub.
