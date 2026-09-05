# Contributing to Shinkiro (蜃気楼)

Thank you for your interest in contributing to **Shinkiro**! We welcome bug reports, protocol decoy pull requests, performance benchmarks, and security improvements.

## How to Contribute

1. Fork the repository and create your feature branch: `git checkout -b feat/my-new-decoy`.
2. Ensure that code complies with Go 1.24+ conventions and formatting (`go fmt ./...`).
3. Run the full test suite with race detector enabled:
   ```bash
   go test -v -race ./...
   ```
4. Verify benchmarks and ensure zero allocations on the hot path:
   ```bash
   make bench
   ```
5. Follow Conventional Commits format (`feat:`, `fix:`, `docs:`, `perf:`). Do **not** add AI attribution trailers or `Co-Authored-By` lines.
6. Open a Pull Request on GitHub.

## Security Architecture Principles

- **Fail-Closed**: Any unhandled error or malformed payload must drop or close safely without panicking.
- **Zero Host Mutation**: Decoys must execute strictly in memory. Never write adversary binaries to disk or execute real host shells.
- **Zero-Footprint**: Use goroutine sandboxes and timeouts to prevent Slowloris resource exhaustion.
