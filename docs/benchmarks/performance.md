# Shinkiro Performance, Scalability & Testing Notes

**Product:** Shinkiro (蜃気楼)  
**Honesty policy:** This page does **not** publish invented microbenchmark tables, fabricated soak-test results, or a nonexistent CI `bench.yml` regression gate. Run the commands below on your hardware and record your own numbers.

---

## 1. Architectural Advantage (qualitative)

Legacy honeypots (Python Cowrie, multi-container T-Pot, etc.) often carry large runtimes or many processes. Shinkiro aims for a **single Go binary**, in-memory decoys, connection deadlines, and no host mutation for attacker commands.

| Concern | Shinkiro approach (code-backed) |
| :--- | :--- |
| Footprint | Single static binary build (`make build`) |
| Slowloris | `SetDeadline` / idle timeout on accepted conns |
| Host mutation | Decoys parse in-memory; no `os/exec` for attacker shells |
| Defense | Export nftables/iptables/sample eBPF **text**; SOAR `block_ip` hooks |
| Supply chain | Cosign `sign-blob` on checksums + Syft SBOM — **not** SLSA L3 |

Head-to-head numeric memory/image claims vs Cowrie/Dionaea/T-Pot that previously appeared here without measurement methodology were **removed**.

---

## 2. How to Run Real Microbenchmarks

Checked-in `Benchmark*` functions today live in `internal/core/multiplexer_bench_test.go`:

- `BenchmarkMultiplexer_ConcurrentConnections`
- `BenchmarkTelemetry_EventIngestionRate`

```bash
make bench
# or
go test -run=^$ -bench=. -benchmem ./internal/core
```

There is **no** `.github/workflows/bench.yml` performance regression workflow in this repository. CI (`.github/workflows/ci.yml`) runs `make test` + `make build` only.

Do not cite historical tables such as `BenchmarkCorrelator_SessionCluster` / `BenchmarkMITRE_TaxonomyLookup` or “74,000,000 events/second” unless you regenerate them from current code and attach raw `go test -bench` output.

---

## 3. Chaos / Concurrency Smoke Tests (real)

```bash
go test -v -race ./tests/chaos
```

`tests/chaos/flood_test.go` defines `TestChaos_ConcurrentConnectionSpike` — a concurrent client spike against an HTTP decoy. Use this as the honest “burst stability” reference, not the older invented log transcript that claimed 1,000 sockets × 15 decoys with scripted PASS lines.

Additional e2e coverage:

```bash
go test -v -race ./tests/e2e
```

---

## 4. Qualitative Comparison Axes (no fake absolute RAM numbers)

When comparing Shinkiro to Cowrie / Dionaea / T-Pot, prefer axes you can verify:

| Axis | What to verify in this repo |
| :--- | :--- |
| Runtime | Pure Go binary vs Python / multi-container |
| Protocol count | 15 decoys under `internal/decoys/` |
| ICS | Native Modbus package |
| Host mutation | In-memory AST / mocks |
| Active defense | Rule **exporters** + SOAR hooks (not live XDP loader) |
| SIEM | CEF / Syslog / ECS / STIX CLI exporters |
| Supply chain | Cosign checksum bundle + Syft SBOM artifacts on Releases |

---

## 5. Deployment Scaling Notes

### Kubernetes / Helm

Chart scaffolding: `deploy/helm/shinkiro` with example resource requests/limits in `values.yaml`. **Image publish to GHCR and config/`services:` wiring remain limited** until a dedicated deploy PR — do not treat `helm install` against `ghcr.io/haiagari/shinkiro` as a verified happy path.

### Edge / cloud VM

A small Linux VM can run `shinkiro up` after `make build` or the install script. Measure CPU/RSS yourself under your scan load.

---

## 6. Optional Kernel Tuning (operator-owned)

If you expose decoys on high-churn Internet links, host sysctl tuning is **your** responsibility. Example parameters (not auto-applied by Shinkiro):

```ini
# /etc/sysctl.d/99-shinkiro-tuning.conf  (optional operator file)
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
```

eBPF JIT sysctls only matter if **you** load an XDP program; Shinkiro does not attach one by itself.

---

## 7. Profiling

```bash
go test -bench=BenchmarkTelemetry_EventIngestionRate -cpuprofile=cpu.prof -memprofile=mem.prof ./internal/core
go tool pprof -alloc_space mem.prof
```

Interpret profiles from your run; do not paste fabricated flamegraph conclusions into docs.

---

## 8. What Was Removed From Prior Docs

- Invented `go test -bench` result blocks with absolute ns/op and “0 allocs/op” marketing.
- Claims of a CI Performance Regression Gate / `.github/workflows/bench.yml`.
- 72-hour soak narratives with scripted goroutine/RSS statistics not backed by checked-in harness output.
- “Cosign + SLSA v1.0” comparison cells — replaced by Cosign `sign-blob` + Syft SBOM only.
