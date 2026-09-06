# Development, Testing & Contributing

For agents and humans changing Shinkiro. Product truth: [`../AGENTS.md`](../AGENTS.md). Contribution workflow summary: [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## 1. Toolchain

- **Go 1.24+** (CI and `go.mod` pin; GeoIP deps keep `golang.org/x/crypto` at **v0.40.0** for Go 1.24 compatibility)
- `make` targets in repo-root `Makefile`
- Optional: Docker, Helm, `kind` / `minikube` for deploy paths

```bash
git clone https://github.com/Haiagari/shinkiro.git
cd shinkiro
make build
make test
```

---

## 2. Make targets

| Target | Action |
| :--- | :--- |
| `make build` | `bin/shinkiro` with version ldflags |
| `make test` | `go test -v -race ./...` |
| `make lint` | `go vet ./...` |
| `make fuzz` | Selected `testing.F` decoy targets (5s each) |
| `make bench` | `go test -bench=. -benchmem ./...` (local; **not** CI-gated) |
| `make e2e` / `e2e-shinkiro` | `scripts/e2e-shinkiro.sh` → all 15 decoys |
| `make docker-build` | Image `shinkiro:local` |
| `make compose-up` | Base compose |
| `make compose-lab` / `compose-edge` | Mode overlays |
| `make compose-down` | Tear down |
| `make helm-lab` / `helm-edge` | Print Helm install recipes |
| `make clean` | Remove `bin/` and `data/` |
| `make run` | `build` then `./bin/shinkiro up` |

---

## 3. E2E — all 15 decoys

```bash
make e2e
# equivalent: go test -count=1 -timeout=120s -race ./tests/e2e/
```

- Registers and probes every real decoy (`ssh` … `modbus`)
- Uses **high unprivileged ports** (Modbus e.g. `29502`)
- **No** privileged netns / `CAP_NET_BIND_SERVICE` required for this smoke

See [`deploy-modes-e2e-ghcr.md`](deploy-modes-e2e-ghcr.md).

---

## 4. Chaos & fuzz

```bash
go test -v -race ./tests/chaos
make fuzz
```

Chaos: concurrent connection spike against an HTTP decoy. Fuzz: Redis, Postgres, Docker, SSH VirtualFS, Modbus parsers.

---

## 5. Package layout (where to change what)

| Area | Path |
| :--- | :--- |
| CLI dispatch | `cmd/shinkiro/*.go` |
| Decoys | `internal/decoys/<protocol>/` |
| Pipeline | `internal/pipeline/` |
| SOAR | `internal/soar/` |
| Intel / correlator / feeds / coverage | `internal/intel/` |
| GeoIP | `internal/intel/geoip/` |
| Cluster hub | `internal/cluster/` |
| TUI | `internal/tui/` |
| PCAP | `internal/pcap/` |
| Defense / eBPF **text** exporters | `internal/defense/`, `internal/ebpf/` |
| Deploy | `deploy/` |

---

## 6. Documentation rules

1. Prefer code reality over marketing.
2. Keep English docs consistent with honesty PRs.
3. Never claim: gossip mesh, SLSA L3, live eBPF loader, invented GeoIP coords, always-on GeoIP without DB, SOAR apply without `--apply`, continuous PCAP, Darwin prebuilts, assumed GHCR.
4. Config examples must use `services:`; playbooks must use `rules`/`if`/`then`.
5. Update [`CHANGELOG.md`](../CHANGELOG.md) Unreleased for user-visible changes.
6. Index new docs from [`docs/README.md`](README.md).

---

## 7. PR expectations

- Conventional Commits (`feat:`, `fix:`, `docs:`, …)
- **No** `Co-Authored-By` / AI attribution trailers
- `go fmt` / `go test -race` green
- Fail-closed sockets; zero host mutation for attacker commands
- Do **not** implement a live eBPF loader in drive-by PRs (exporter-only remains the contract)

---

## 8. Release notes for developers

- Release workflow builds Linux amd64/arm64 binaries, checksums, Cosign `sign-blob`, Syft SBOMs
- Optional GHCR when repository variable `PUSH_GHCR=true`
- Installer: `scripts/install.sh` (Linux only)

See [`getting-started.md`](getting-started.md) and [`honesty-limitations.md`](honesty-limitations.md).
