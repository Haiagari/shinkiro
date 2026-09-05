# Core Engine Specification

## Purpose
Single-binary Go network listener multiplexer that spawns isolated goroutines for configured honeypot ports with memory caps, idle timeouts, and graceful shutdown.

## Requirements

### Requirement: CORE-1 — Multi-Port Listener Multiplexing
The engine MUST bind to configured ports concurrently and route connections to protocol-specific decoys.

#### Scenario: Normal startup with multiple decoys
- GIVEN a configuration specifying ports 2222 (SSH), 6379 (Redis), 2375 (Docker)
- WHEN `shinkiro up` is executed
- THEN listeners for all 3 ports start concurrently without blocking
- AND a status signal is emitted

#### Scenario: Port collision or permission failure
- GIVEN a port that is already in use or requires root privileges without proper caps
- WHEN `shinkiro up` attempts to bind
- THEN the engine logs a structured error, frees previously bound ports, and exits fail-closed with status 1

### Requirement: CORE-2 — Connection Sandboxing & Limits
Every incoming connection MUST be wrapped in a context with an enforce-able timeout (default: 30s) and bounded read/write buffers.

#### Scenario: Slowloris / stalled attacker connection
- GIVEN an active connection that sends no bytes for 30 seconds
- WHEN the idle deadline fires
- THEN the engine closes the socket and records a timeout event in telemetry
