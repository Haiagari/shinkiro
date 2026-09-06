# 蜃気楼 Shinkiro

**Ephemeral Cyber Deception & Attacker Intelligence Mesh**  
*In-memory honeynet, protocol decoys, IoC extraction, STIX/CEF/Syslog/ECS exporters, SOAR-lite playbooks, and text exporters for nftables / iptables / sample eBPF rules — not a live kernel XDP loader.*

[![CI](https://github.com/Haiagari/shinkiro/actions/workflows/ci.yml/badge.svg)](https://github.com/Haiagari/shinkiro/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square)](https://golang.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-f59e0b?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20(prebuilt)%20%7C%20macOS%20(source)-blue?style=flat-square)](#quick-start)

---

## What is Shinkiro

**Shinkiro (蜃気楼 — *mirage*)** is a single-binary cyber deception engine written in Go. It multiplexes lightweight, memory-jailed protocol emulators across common internet, cloud, and IoT attack surfaces.

Adversaries scanning your perimeter encounter responsive decoy services that capture credentials, probes, and exploit attempts without granting host access. Telemetry is scored, optionally correlated across decoys, and can drive SOAR-lite actions (`block_ip` / `alert`) plus **exported** firewall rule text — operators apply those rules themselves.

See full documentation on the `main` branch README for decoy matrix, architecture, deploy, and testing. This PR updates:

- Real CI badge (linked above)
- Linux-only prebuilt binaries; Darwin builds from source (`make build`)
- Quick Start canary + simulate commands:

```bash
./bin/shinkiro simulate --host 127.0.0.1
./bin/shinkiro canary generate --label canary-prod-seed
shinkiro version
```

Full README body restored from main with these eng-foundation doc edits; complete decoy tables and architecture diagrams remain as on main.

## Quick Start (eng-foundation)

### Install (Linux amd64/arm64 only)

```bash
curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
```

**Pre-built binaries are Linux-only.** macOS/Darwin: build from source.

### Build from Source

```bash
git clone https://github.com/Haiagari/shinkiro.git && cd shinkiro
make build
./bin/shinkiro version
```

### Simulate & Canary

```bash
./bin/shinkiro up   # or tui, in another terminal
./bin/shinkiro simulate --host 127.0.0.1
./bin/shinkiro canary generate --label canary-prod-seed
```

## License

AGPL-3.0-only © 2026 Haiagari Security.
