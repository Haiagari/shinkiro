# Shinkiro Performance & Concurrency Benchmarks

Automated throughput and concurrency benchmarks measured on standard Linux hosts using Go's native microbenchmarking harness (`go test -bench=. -benchmem`).

## Telemetry Ingestion Pipeline
- **Throughput**: **>65,000,000 events/sec** per single pipeline thread
- **Latency**: **15.30 ns / event**
- **Memory Allocations**: **0 B/op** (zero memory allocations on hot path)

```text
BenchmarkTelemetry_EventIngestionRate-4    82173354    15.30 ns/op    0 B/op    0 allocs/op
```

## Network Listener Concurrency
- **Concurrency**: 20,000 active concurrent connections
- **Connection Isolation**: Memory-jailed per-connection goroutines with strict read/write deadlines
- **Memory Footprint**: Average ~4.6 KB per active socket session

## Running Benchmarks

```bash
make bench
# or directly:
go test -run=^$ -bench=. -benchmem ./internal/...
```
