# Getting Started — Install, Build & First Run

This guide covers installing Shinkiro, verifying the binary, and running the mesh for the first time. For deeper CLI flags see [`cli-reference.md`](cli-reference.md). For honesty constraints see [`honesty-limitations.md`](honesty-limitations.md).

---

## 1. Requirements

| Requirement | Notes |
| :--- | :--- |
| **Linux** for prebuilt binaries | amd64 or arm64 release assets |
| **Go 1.24+** | Only needed for build-from-source / tests |
| **Root or `CAP_NET_BIND_SERVICE`** | Only if binding privileged ports (e.g. Modbus `:502`); default config uses `:502` for Modbus — remapped high ports work unprivileged (see e2e) |
| **Optional** MaxMind `.mmdb` | GeoIP enrichment; product works without it |
| **Optional** Docker / Helm | Compose lab/edge and Kubernetes paths |

---

## 2. Install prebuilt binary (Linux)

Release CI publishes **raw binaries** (not GoReleaser tarballs):

| Asset | Example |
| :--- | :--- |
| Binary | `shinkiro-linux-amd64`, `shinkiro-linux-arm64` |
| Checksums | `checksums.txt` (SHA-256) |
| Signature | `checksums.bundle` (Cosign `sign-blob` on checksums) |
| SBOM | `shinkiro-sbom.spdx.json`, `shinkiro-sbom.cdx.json` (Syft) |

```bash
# Latest release (resolves tag via GitHub Releases API)
curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh

# Pin a version
SHINKIRO_VERSION=v1.0.0 curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh

# Custom install directory
INSTALL_DIR="$HOME/bin" SHINKIRO_VERSION=v1.0.0 \
  curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
```

**Honesty:**

- Prebuilt = **Linux only**. On Darwin the installer prints build-from-source instructions and exits non-zero.
- Cosign verifies the **checksum file** blob signature in release CI artifacts; the installer verifies SHA-256 of the binary against `checksums.txt` when present.
- This is **not** SLSA Level 3 provenance.

Verify:

```bash
shinkiro version
# Shinkiro <ver> (commit=… date=…) — High-Interaction Deception Engine (Haiagari Security)
```

---

## 3. Build from source

```bash
git clone https://github.com/Haiagari/shinkiro.git
cd shinkiro
make build
./bin/shinkiro version
```

`LDFLAGS` inject `main.version`, `main.commit`, `main.date` (see `Makefile`).

Useful Make targets (full list in [`development.md`](development.md)):

```bash
make test          # go test -race ./...
make fuzz          # selected testing.F targets
make e2e           # all 15 decoys on high ports
make docker-build  # shinkiro:local
make compose-lab   # lab overlay
make compose-edge  # edge overlay
```

---

## 4. Configuration files

Working directory should contain (or path via tooling):

| File | Role |
| :--- | :--- |
| `config.yaml` | `node_name`, timeouts, `audit_log_path`, `metrics_port`, **`services:`** map |
| `playbooks.yaml` | SOAR-lite `rules` / `if` / `then` |

Runtime key is **`services:`** (not `decoys:`). Default enables all **15** decoys (SSH `:2222` … Modbus `:502`). Copy from repo root when installing a binary alone:

```bash
# Example: run from a directory that has config + playbooks
cp /path/to/shinkiro/config.yaml .
cp /path/to/shinkiro/playbooks.yaml .
mkdir -p data
```

---

## 5. First run — headless mesh

```bash
# Dry-run SOAR (default) — prints firewall text, does not exec
./bin/shinkiro up

# Optional GeoIP
export SHINKIRO_GEOLITE2_PATH=/var/lib/GeoIP/GeoLite2-City.mmdb
./bin/shinkiro up --geoip-db "$SHINKIRO_GEOLITE2_PATH"

# Live firewall apply (explicit)
./bin/shinkiro up --apply
# or: SHINKIRO_SOAR_APPLY=1 ./bin/shinkiro up
```

Startup banner reports:

- Active decoy ports from `services:`
- Metrics URL if `metrics_port` > 0 (default `:9100`)
- Pipeline stage order and SOAR mode (`dry-run` vs live)
- GeoIP enabled/disabled
- On-demand PCAP threshold and directory

Stop with `Ctrl+C` (graceful multiplexer shutdown).

---

## 6. First run — TUI dashboard

```bash
./bin/shinkiro tui
./bin/shinkiro tui --apply   # live block_ip for playbooks + key `b`
```

Press `?` for keybindings. Details: [`architecture/tui-operator.md`](architecture/tui-operator.md), [`operator-guide.md`](operator-guide.md).

---

## 7. Smoke the mesh with simulate

In a second terminal (mesh must be listening):

```bash
./bin/shinkiro simulate --host 127.0.0.1
```

Runs `internal/adversary` default scenarios against local decoy ports.

---

## 8. Docker lab / edge (optional)

```bash
make compose-lab    # demo mounts from deploy/modes/lab/
make compose-edge   # hardened overlay; dry-run SOAR
```

Full steps: [`../deploy/README.md`](../deploy/README.md), [`../deploy/modes/README.md`](../deploy/modes/README.md).

---

## 9. Verify supply-chain artifacts (optional)

From a GitHub Release for tag `vX.Y.Z`:

1. Download `checksums.txt`, `checksums.bundle`, binary, SBOMs.
2. Verify SHA-256 of the binary matches `checksums.txt`.
3. Verify Cosign blob signature on checksums (operator tooling; see release notes / Cosign docs).
4. Do **not** expect SLSA L3 attestation files.

---

## Next steps

- [CLI reference](cli-reference.md) — every command  
- [Operator guide](operator-guide.md) — TUI / SOAR / PCAP  
- [Event pipeline](architecture/event-pipeline.md) — Score → Sink  
- [Honesty & limitations](honesty-limitations.md) — what not to claim  
