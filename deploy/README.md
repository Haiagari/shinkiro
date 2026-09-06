# Deploying Shinkiro

Honest deploy paths for **Docker Compose** and **Helm**. There is **no assumed GHCR image** today — release CI publishes Linux binaries to GitHub Releases only (see `.github/workflows/release.yml`). Prefer a **local image build**.

## Prerequisites

- Docker (Compose v2)
- Optional: Helm 3 + a cluster (kind / minikube / k3d / remote)
- Go 1.24+ only if building the binary outside Docker

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
| Image | Local tag only — **do not** assume `ghcr.io/haiagari/shinkiro` exists |

Render / lint without a cluster:

```bash
helm template shinkiro ./deploy/helm/shinkiro | head -100
helm lint ./deploy/helm/shinkiro
```

### Config model

Runtime YAML uses top-level **`services:`** (not `decoys:`). Edit `deploy/helm/shinkiro/files/config.yaml` (kept in sync with repo-root `config.yaml` for the chart) and reinstall/upgrade, or patch the ConfigMap after install.

## Future GHCR

A GHCR publish workflow is **out of scope** until release CI grows an image job. When that lands, update `values.yaml` `image.repository` and this README — do not claim a registry path that CI does not publish.
