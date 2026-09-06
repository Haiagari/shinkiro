# Deploying Shinkiro

Honest deploy paths for **Docker Compose** and **Helm**, plus **lab / edge** deploy modes.

- **Default:** build a **local** image (`shinkiro:local`). Release CI always publishes Linux binaries to GitHub Releases.
- **Optional GHCR:** only when repository variable `PUSH_GHCR=true` — then tags push to `ghcr.io/haiagari/shinkiro`. Do not assume the image exists otherwise.

Docs index: [`../docs/README.md`](../docs/README.md) · Modes detail: [`modes/README.md`](modes/README.md) · E2E/GHCR: [`../docs/deploy-modes-e2e-ghcr.md`](../docs/deploy-modes-e2e-ghcr.md)

---

## Prerequisites

- Docker (Compose v2)
- Optional: Helm 3 + a cluster (kind / minikube / k3d / remote)
- Go 1.24+ only if building the binary outside Docker

---

## Deploy modes (lab vs edge)

| Mode | Command | Notes |
| --- | --- | --- |
| **lab** | `make compose-lab` | Demo mounts from `deploy/modes/lab/`; dry-run SOAR; keeps `NET_ADMIN`/`NET_RAW` from base compose for optional apply experiments |
| **edge** | `make compose-edge` | Hardened overlay (`read_only`, `cap_drop: ALL` + `NET_BIND_SERVICE`, quieter PCAP/playbooks); **does not** set `SHINKIRO_SOAR_APPLY` |
| (legacy) | `make compose-up` | Baked image `config.yaml` only — backward compatible |

```bash
make helm-lab
make helm-edge
```

Live firewall apply remains opt-in in **every** mode (`--apply` / `SHINKIRO_SOAR_APPLY=1`).

---

## Docker Compose

```bash
make docker-build
make compose-up
make compose-lab
make compose-edge
docker compose -f deploy/docker/docker-compose.yml up --build -d
```

| Piece | Behavior |
| --- | --- |
| Image | Built from `deploy/docker/Dockerfile` → binary at `/usr/local/bin/shinkiro` |
| Config | `config.yaml` + `playbooks.yaml` baked into `/app`. Lab/edge overlays bind-mount mode files. |
| Data | Host data dir → `/app/data` so `data/events.jsonl` persists |
| Ports | All decoys enabled in default / mode `services:`, plus metrics `:9100` |
| Command | `shinkiro up` (dry-run SOAR unless you set apply env yourself) |

```bash
docker compose -f deploy/docker/docker-compose.yml ps
curl -sf http://127.0.0.1:9100/metrics | head
docker compose -f deploy/docker/docker-compose.yml logs -f shinkiro
make compose-down
```

Optional GeoIP inside Compose: mount a `.mmdb` and set `SHINKIRO_GEOLITE2_PATH` (do not commit `.mmdb` files).

---

## Helm

Chart path: `deploy/helm/shinkiro`.

```bash
make docker-build
kind load docker-image shinkiro:local

helm install shinkiro ./deploy/helm/shinkiro \
  --namespace security \
  --create-namespace \
  --set image.repository=shinkiro \
  --set image.tag=local \
  --set image.pullPolicy=IfNotPresent
```

Lab / edge recipes: see [`modes/README.md`](modes/README.md) or `make helm-lab` / `make helm-edge`.

| Piece | Behavior |
| --- | --- |
| Command | `/usr/local/bin/shinkiro up` |
| ConfigMap | Mounts config + playbooks at `/app/` (`services:` key) |
| Data | `emptyDir` at `/app/data` |
| Seccomp | Pod `seccompProfile.type: RuntimeDefault`; optional seccomp JSON mount |
| Capabilities | `drop: [ALL]`, `add: [NET_BIND_SERVICE]` for Modbus `:502` |
| Image | Local tag by default; optional GHCR only if published |

```bash
helm template shinkiro ./deploy/helm/shinkiro | head -100
helm lint ./deploy/helm/shinkiro
```

---

## Optional GHCR

When `PUSH_GHCR=true`, release job pushes `ghcr.io/haiagari/shinkiro:<tag>` and `:latest`. Binary + SBOM + Cosign path always runs. When unset, keep using `shinkiro:local`.

```bash
helm upgrade --install shinkiro ./deploy/helm/shinkiro \
  --set image.repository=ghcr.io/haiagari/shinkiro \
  --set image.tag=v1.1.0 \
  --set image.pullPolicy=IfNotPresent
```

---

## Other deploy scaffolding

| Path | Notes |
| :--- | :--- |
| `deploy/systemd/` | Unit file for binary installs |
| `deploy/ansible/playbook.yml` | Ansible scaffolding — verify before production use |
| `deploy/prometheus/` / `deploy/grafana/` | Example scrape/dashboard assets |
| `deploy/terraform/` | Infrastructure scaffolding |
| `deploy/security/seccomp.json` | Operator-applied seccomp profile |

These helpers are **operator-owned**; they do not change the honesty contract (no gossip cluster, no live eBPF loader, dry-run SOAR default).
