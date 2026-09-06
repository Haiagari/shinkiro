# Deploying Shinkiro

Honest deploy paths for **Docker Compose** and **Helm**, plus **lab / edge** deploy modes.

- **Default:** build a **local** image (`shinkiro:local`). Release CI always publishes Linux binaries to GitHub Releases.
- **Optional GHCR:** only when repository variable `PUSH_GHCR=true` — then tags push to `ghcr.io/haiagari/shinkiro` (see below). Do not assume the image exists otherwise.

## Prerequisites

- Docker (Compose v2)
- Optional: Helm 3 + a cluster (kind / minikube / k3d / remote)
- Go 1.24+ only if building the binary outside Docker


## Deploy modes (lab vs edge)

| Mode | Command | Notes |
| --- | --- | --- |
| **lab** | `make compose-lab` | Demo mounts from `deploy/modes/lab/`; dry-run SOAR; keeps `NET_ADMIN`/`NET_RAW` from base compose for optional apply experiments |
| **edge** | `make compose-edge` | Hardened overlay (`read_only`, `cap_drop: ALL` + `NET_BIND_SERVICE`, quieter PCAP/playbooks); **does not** set `SHINKIRO_SOAR_APPLY` |
| (legacy) | `make compose-up` | Baked image `config.yaml` only — backward compatible |

Full details: [`modes/README.md`](modes/README.md).

Helm helpers print install lines (cluster not required to print):

```bash
make helm-lab
make helm-edge
```

## Docker Compose

From the repository root:

```bash
# Build image tagged shinkiro:local and start the stack
make docker-build
make compose-up

# Equivalent one-liner
docker compose -f deploy/docker/docker-compose.yml up --build -d
```

What this does:

| Piece | Behavior |
| --- | --- |
| Image | Built from `deploy/docker/Dockerfile` → binary at `/usr/local/bin/shinkiro` |
| Config | `config.yaml` + `playbooks.yaml` baked into `/app` (CWD). Optional host bind-mounts are commented in the Compose file. |
| Data | Host `./deploy/docker/data` → `/app/data` so `data/events.jsonl` persists |
| Ports | All decoys enabled in default `config.yaml`, plus metrics `:9100` |

Useful checks:

```bash
docker compose -f deploy/docker/docker-compose.yml ps
curl -sf http://127.0.0.1:9100/metrics | head
docker compose -f deploy/docker/docker-compose.yml logs -f shinkiro
docker compose -f deploy/docker/docker-compose.yml down
```

## Helm

Chart path: `deploy/helm/shinkiro`.

1. **Build and load a local image** (no GHCR pull):

```bash
make docker-build
# kind example:
kind load docker-image shinkiro:local
# minikube example:
# minikube image load shinkiro:local
```

2. **Install**:

```bash
helm install shinkiro ./deploy/helm/shinkiro \
  --namespace security \
  --create-namespace \
  --set image.repository=shinkiro \
  --set image.tag=local \
  --set image.pullPolicy=IfNotPresent
```

Defaults already use `repository: shinkiro`, `tag: local`, `pullPolicy: IfNotPresent`.

3. **What the chart wires**:

| Piece | Behavior |
| --- | --- |
| Command | `/usr/local/bin/shinkiro up` (matches Dockerfile) |
| ConfigMap | Mounts `files/config.yaml` + `files/playbooks.yaml` at `/app/` |
| Data | `emptyDir` at `/app/data` for `data/events.jsonl` |
| Seccomp | Pod `seccompProfile.type: RuntimeDefault`; optional mount of `files/seccomp.json` at `/etc/shinkiro/seccomp.json` |
| Capabilities | `drop: [ALL]`, `add: [NET_BIND_SERVICE]` for Modbus `:502` |
| Image | Local tag by default; optional `ghcr.io/haiagari/shinkiro` only if `PUSH_GHCR=true` |

Render / lint without a cluster:

```bash
helm template shinkiro ./deploy/helm/shinkiro | head -100
helm lint ./deploy/helm/shinkiro
```

### Config model

Runtime YAML uses top-level **`services:`** (not `decoys:`). Edit `deploy/helm/shinkiro/files/config.yaml` (kept in sync with repo-root `config.yaml` for the chart) and reinstall/upgrade, or patch the ConfigMap after install.

## Optional GHCR

Release workflow job `push-ghcr` runs **only** when the repository variable `PUSH_GHCR` is set to `true`. It logs into `ghcr.io` with `GITHUB_TOKEN` (`packages: write`) and pushes:

- `ghcr.io/haiagari/shinkiro:<tag>` (e.g. `v1.1.0`)
- `ghcr.io/haiagari/shinkiro:latest`

Binary + SBOM + Cosign checksum signing continue regardless. When `PUSH_GHCR` is unset/false, **no** image is published — keep using `shinkiro:local`.

```bash
# After a tag release with PUSH_GHCR=true:
helm upgrade --install shinkiro ./deploy/helm/shinkiro \
  --set image.repository=ghcr.io/haiagari/shinkiro \
  --set image.tag=v1.1.0 \
  --set image.pullPolicy=IfNotPresent
```
