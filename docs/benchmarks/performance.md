# Shinkiro Performance, Scalability & Testing Notes

**Product:** Shinkiro (蜃気楼)  
**Honesty policy:** This page does **not** publish invented microbenchmark tables, fabricated soak-test results, or a nonexistent CI `bench.yml` regression gate. Run the commands below on your hardware and record your own numbers.

Docs hub: [`../README.md`](../README.md) · Development: [`../development.md`](../development.md)

---

## 1. Architectural advantage (qualitative)

Legacy honeypots (Python Cowrie, multi-container T-Pot, etc.) often carry large runtimes or many processes. Shinkiro aims for a **single Go binary**, in-memory decoys, connection deadlines, and no host mutation for attacker commands.

| Concern | Shinkiro approach (code-backed) |
| :--- | :--- |
| Footprint | Single static binary build (`make build`) |
| Slowloris | `SetDeadline` / idle timeout on accepted conns |
| Host mutation | Decoys parse in-memory; no `os/exec` for attacker shells |
| Defense | Export nftables/iptables/sample eBPF **text**; SOAR `block_ip` dry-run/apply |
| Supply chain | Cosign `sign-blob` on checksums + Syft SBOM — **not** SLSA L3 |

---

## 2. How to run real microbenchmarks

Checked-in `Benchmark*` functions today live in `internal/core/multiplexer_bench_test.go`:

- `BenchmarkMultiplexer_ConcurrentConnections`
- `BenchmarkTelemetry_EventIngestionRate`

```bash
make bench
# or
go test -run=^$ -bench=. -benchmem ./internal/core
```

There is **no** `.github/workflows/bench.yml` performance regression workflow. CI (`.github/workflows/ci.yml`) runs `make test` + `make build` only.

Do not cite historical invented ns/op tables unless you regenerate them from current code and attach raw `go test -bench` output.

---

## 3. Chaos / concurrency / e2e

```bash
go test -v -race ./tests/chaos
make e2e
```

`tests/chaos` defines concurrent client spike coverage. `make e2e` probes all **15** real decoys on high unprivileged ports.

---

## 4. Qualitative comparison axes (no fake absolute RAM numbers)

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

## 5. Deployment scaling notes

### Kubernetes / Helm

Chart: `deploy/helm/shinkiro` with lab/edge values. Default image is **local** (`shinkiro:local`). Optional GHCR only when `PUSH_GHCR=true` published an image — see [`../../deploy/README.md`](../../deploy/README.md).

### Edge / cloud VM

A small Linux VM can run `shinkiro up` after `make build` or the install script. Measure CPU/RSS yourself under your scan load.

---

## 6. Optional kernel tuning (operator-owned)

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

## 8. What was removed from prior docs

- Invented `go test -bench` result blocks with absolute ns/op marketing
- Claims of a CI Performance Regression Gate / `.github/workflows/bench.yml`
- 72-hour soak narratives without checked-in harness output
- "Cosign + SLSA v1.0" comparison cells — replaced by Cosign `sign-blob` + Syft SBOM only
