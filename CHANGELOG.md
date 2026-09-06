# Changelog

All notable changes to **Shinkiro** are documented in this file following [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Deploy modes lab vs edge** (`deploy/modes/`): lab (demo-friendly) and edge (hardened defaults — dry-run SOAR, quieter playbook/PCAP thresholds). Compose overlays `compose.lab.yml` / `compose.edge.yml`; Helm `values-lab.yaml` / `values-edge.yaml` with optional `--set-file` config overrides. Docs: `deploy/modes/README.md`. Makefile: `compose-lab`, `compose-edge`, `helm-lab`, `helm-edge`.
- **E2E for all 15 decoys**: `tests/e2e/e2e_all_decoys_{test,run,probes}_test.go` register and probe every real decoy (`ssh`…`modbus`); `make e2e` / `make e2e-shinkiro` → `scripts/e2e-shinkiro.sh`. Uses high unprivileged ports (Modbus `29502`) — **no** privileged netns / `CAP_NET_BIND_SERVICE` required.
- **Optional GHCR on release**: `.github/workflows/release.yml` job `push-ghcr` publishes `ghcr.io/haiagari/shinkiro` when repository variable `PUSH_GHCR=true` (login via `GITHUB_TOKEN` / `packages:write`). Binary release path unchanged when the variable is unset.

- **Campaign correlator v2** (`internal/intel/correlator.go`): multi-event grouping by same source IP + sliding session window + decoy hop path; tracks technique IDs, event/action rolls, ordered hop path, and explicit grouping reasons (rule-based - **not ML**). CLI: `shinkiro campaigns [--format table|json]`.
- **ThreatFox / AbuseIPDB CLI**: real HTTP clients (`internal/intel/feeds.go`) with `THREATFOX_API_KEY` / `ABUSEIPDB_API_KEY`; graceful errors when keys are missing. Commands: `shinkiro threatfox --search|--days`, `shinkiro abuseipdb --ip`.
- **ATT&CK coverage report**: `shinkiro coverage` / `attack-coverage` maps decoy-matrix.md technique tags (+ optional `--runtime-mapper` for `MapToMitre`) to table/JSON - no invented ATT&CK mappings.

- **TUI operator actions** (`internal/tui`): select high-score events / correlator campaigns; trigger SOAR `block_ip` (dry-run by default, live only with `--apply` / `SHINKIRO_SOAR_APPLY=1`), operator on-demand PCAP (`CaptureNow`), adversary `simulate`, and AWS canary generation; help overlay + clearable status (see `docs/architecture/tui-operator.md`).
- **`pcap.OnDemandCapture.CaptureNow`**: explicit operator capture that writes libpcap frames regardless of score threshold (filename prefix `operator-`).
- **Unified event pipeline** (`internal/pipeline`): in-process Event → Score → Correlate → Playbook → Sink bus; `shinkiro up` / `tui` feed decoy emit channels through ordered stages (see `docs/architecture/event-pipeline.md`).
- **SOAR `block_ip` apply path** (`internal/soar.BlockApplier`): generates real `nftables`/`iptables` command text via `internal/defense`; **dry-run by default**; live exec + optional webhook POST only with `--apply` or `SHINKIRO_SOAR_APPLY=1` (no fake kernel auto-block claims).
- **On-demand PCAP** (`internal/pcap.OnDemandCapture`): when threat score ≥ threshold (default 80), writes libpcap 2.4 forensic frames under `data/pcap/` using the existing writer; wired into the pipeline sink.
- **Version via ldflags:** `main.version` / `main.commit` / `main.date` injected by Makefile, release CI, Dockerfile build args, and `.goreleaser.yml` (`shinkiro version` prints them).
- **Real CI badge** linked to `.github/workflows/ci.yml` (replaces the removed static tests-passing badge).
- **Quick Start:** documented real `simulate --host` and `canary generate --label` CLI usage after install/build.

### Changed
- **go.mod:** direct requires for `bubbletea`, `lipgloss`, `golang.org/x/crypto`, `gopkg.in/yaml.v3` (go 1.24 unchanged); transitive deps remain `indirect`.
- **CLI exit status:** no arguments and unknown commands now exit non-zero (`os.Exit(1)`).
- **cmd/shinkiro layout:** `main.go` holds version ldflags vars + dispatch; handlers live in sibling package files (`usage.go`, `up.go`, `canary_cmd.go`, `simulate.go`, `export_siem.go`, `cluster_kernel.go`).
- **Docs:** clarified Linux-only prebuilt binaries; Darwin requires build-from-source.
- **`intel.Engine.Persist`:** sink-stage JSONL/blocklist write without re-ingesting the correlator (pipeline owns Score/Correlate).
- **`shinkiro tui`:** Bubbletea dashboard wired to intel Engine, SOAR BlockApplier, and on-demand PCAP (same process as `up`).

### Fixed
- `scripts/install.sh` now downloads real GitHub Release assets (`shinkiro-linux-amd64` / `shinkiro-linux-arm64`), verifies `checksums.txt` when present, and no longer falls back to nonexistent `v0.2.0` or GoReleaser-style `shinkiro_${VER}_${os}_${arch}.tar.gz` names.
- **Docker / Helm runnable:** Dockerfile installs the binary at `/usr/local/bin/shinkiro`, copies `config.yaml` + `playbooks.yaml` into `/app` (and `/etc/shinkiro`), and uses `WORKDIR /app` so `data/events.jsonl` persists via the `/app/data` volume.
- **docker-compose.yml:** mounts `./data` → `/app/data`, exposes ports for all decoys enabled in default `config.yaml` (+ metrics `:9100`), image tag `shinkiro:local`.
- **Helm chart:** container command `/usr/local/bin/shinkiro up`; ConfigMaps for config/playbooks and optional seccomp JSON; honest defaults `image.repository=shinkiro`, `tag=local`, `pullPolicy=IfNotPresent` (no assumed GHCR image); `NET_BIND_SERVICE` for Modbus `:502`; pod `seccompProfile: RuntimeDefault`.

### Documentation
- **TUI operator guide:** `docs/architecture/tui-operator.md` — keybindings, dry-run vs apply, PCAP/simulate/canary honesty notes.
- **Event pipeline guide:** `docs/architecture/event-pipeline.md` — dry-run vs apply SOAR, PCAP threshold/env, stage order.
- **Honesty pass:** README, AGENTS.md, architecture, benchmarks, decoy matrix, threat-intel, and threat-scoring docs aligned with implemented behavior:
  - eBPF/XDP described as rule exporters + sample C (`internal/ebpf`), not a live kernel loader / `BPF_MAP_UPDATE`.
  - GeoIP described as demo/heuristic prefixes, not MaxMind.
  - Cluster described as HTTP ingest hub, not encrypted UDP gossip.
  - PCAP: on-demand high-score capture wired into pipeline sink (not continuous mirror of every socket).
  - Supply chain described as Cosign `sign-blob` on checksums + Syft SBOM only (no SLSA Level 3 claim).
  - Invented benchmark tables / nonexistent `bench.yml` gate removed; point to real `Benchmark*` and `tests/chaos`.
  - Playbook examples match real `rules` / `if` / `then` / `block_ip` schema.
  - Config examples use `services:` (runtime key), not `decoys:`.
  - Helm / Compose deploy docs match local-image workflow (`deploy/README.md`); no decoys.* values key.
  - Removed static `tests-passing` badge that was not CI-linked.

## [v1.0.0] - 2026-09-05

### Added
- **Modbus/TCP Industrial Decoy (`:502`)**: ICS/SCADA PLC emulator supporting MBAP framing, holding registers, coils, and MITRE for ICS `T0855` mapping.
- **SOAR-Lite Playbook Automation Engine**: Declarative YAML playbooks (`playbooks.yaml`) with `rules` / `if` / `then` actions (`block_ip`, `alert`, `tag`).
- **Enterprise SIEM Exporters**: ArcSight CEF, RFC5424 Syslog, Elastic Common Schema (ECS v8.x), STIX 2.1, and ThreatFox-oriented feed helpers.
- **Multi-Protocol Campaign Correlator**: Cross-protocol adversary session aggregation with scoring and velocity multipliers.
- **Kubernetes Helm Chart (scaffolding)**: Chart under `deploy/helm/shinkiro` with strict securityContext fields; image registry / config wiring still limited (see Unreleased honesty note).
- **Fuzzing Suite**: Native Go fuzz tests (`testing.F`) across selected protocol parsers via `make fuzz`.
- **Supply Chain Artifacts**: Sigstore Cosign keyless **`sign-blob`** on `checksums.txt`, Anchore Syft SBOM (SPDX & CycloneDX). Does **not** include SLSA Level 3 provenance attestations.
- **Telnet IoT Botnet Decoy (`:2323`)**: BusyBox-style embedded Linux router, IAC negotiation, Mirai-style credential capture.
- **MQTT Broker Decoy (`:1883`)**: MQTT v3.1.1 protocol parser trapping unauthorized IoT client connections.
- **PCAP Writer Package**: Libpcap 2.4 format writer (`internal/pcap`) for optional forensic dumps — **not yet wired** into the live multiplexer / `cmd/shinkiro` path.
- **SMB/CIFS Decoy (`:4445`)**: NetBIOS session and SMBv2 negotiate parser for EternalBlue-style reconnaissance.
- **Decoys Matrix Documentation**: MITRE ATT&CK mapping and threat score taxonomy in `docs/decoys/decoy-matrix.md`.

## [v0.4.0] - 2026-09-05

### Note
- Tag `v0.4.0` was published with linux amd64/arm64 release binaries, checksums, SBOMs, and cosign artifacts. This changelog section records that release for Keep-a-Changelog continuity.

### Added (at tag time)
- Release assets and supply-chain artifacts for the v0.4.0 cut (binaries + checksums + Syft SBOM + Cosign checksum bundle).

## [v0.2.0] - 2026-09-04

### Added
- **AWS IMDS Decoy (`:8169`)**: EC2 Instance Metadata Service emulator (IMDSv1 & IMDSv2) for SSRF traps targeting IAM role credential paths.
- **Sample C eBPF / XDP Filter + Go Rule Exporter**: Sample program at `internal/ebpf/c/xdp_drop.c` and Go `FilterManager.RenderScript()` emitting rule text — not a userspace live loader.
- **STIX 2.1 Threat Intelligence Exporter**: `shinkiro stix` transforming observed honeypot interactions into STIX 2.1 JSON bundles.
- **Heuristic GeoIP Resolver**: Offline demo/prefix-based enrichment (`internal/intel/geoip`) — not a MaxMind database engine.
- **Distributed Cluster HTTP Hub**: Multi-node HTTP aggregation (`shinkiro cluster hub`) for edge sensors to POST events to a central ingest endpoint.

## [v0.1.0] - 2026-09-04

### Added
- Initial release of Shinkiro deception engine in Go.
- Core Multiplexer and in-memory decoys (SSH, Redis, Docker, HTTP, PostgreSQL, K8s).
- Live Bubbletea Terminal Dashboard (`shinkiro tui`).
- Dynamic firewall mitigation **text export** (`iptables`, `nftables`).
