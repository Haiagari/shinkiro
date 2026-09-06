# Deploy modes: lab vs edge

Shinkiro ships two **honest** deploy profiles. Neither claims a live cluster gossip fabric or automatic kernel XDP enforcement.

| Mode | Intent | SOAR `block_ip` | Noise | Caps / hardening |
| :--- | :--- | :--- | :--- | :--- |
| **lab** | Local demos, CI smoke, developer laptops | Dry-run by default (same as binary) | Demo-friendly playbook thresholds | Compose keeps `NET_ADMIN` / `NET_RAW` so optional `--apply` can be tried |
| **edge** | Production-ish edge sensors | Dry-run by default; overlays **do not** set `SHINKIRO_SOAR_APPLY` | Higher playbook thresholds; `SHINKIRO_PCAP_THRESHOLD=90` | Drop `ALL`, add `NET_BIND_SERVICE` only; read-only rootfs + `no-new-privileges` |

Both modes still expose the **15** decoys via their `services:` configs.

Parent deploy guide: [`../README.md`](../README.md).

---

## Select a mode

### Docker Compose

```bash
make compose-lab
# docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/compose.lab.yml up -d

make compose-edge
# docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/compose.edge.yml up -d
```

Plain `make compose-up` keeps the previous single-file path (baked `config.yaml` in the image) for backward compatibility.

### Helm

```bash
make docker-build
kind load docker-image shinkiro:local

helm upgrade --install shinkiro ./deploy/helm/shinkiro \
  --namespace security --create-namespace \
  -f deploy/helm/shinkiro/values-lab.yaml \
  --set-file configOverride=deploy/modes/lab/config.yaml \
  --set-file playbooksOverride=deploy/modes/lab/playbooks.yaml \
  --set image.repository=shinkiro --set image.tag=local --set image.pullPolicy=IfNotPresent

helm upgrade --install shinkiro ./deploy/helm/shinkiro \
  --namespace security --create-namespace \
  -f deploy/helm/shinkiro/values-edge.yaml \
  --set-file configOverride=deploy/modes/edge/config.yaml \
  --set-file playbooksOverride=deploy/modes/edge/playbooks.yaml \
  --set image.repository=shinkiro --set image.tag=local --set image.pullPolicy=IfNotPresent
```

Makefile helpers: `make helm-lab` / `make helm-edge` (print the exact commands; they do not assume a cluster).

---

## Files

| Path | Role |
| :--- | :--- |
| `lab/config.yaml` / `lab/playbooks.yaml` | All 15 decoys; demo playbook thresholds |
| `edge/config.yaml` / `edge/playbooks.yaml` | All 15 decoys; quieter thresholds / longer idle |
| `../docker/compose.lab.yml` | Mounts lab configs + lab node env |
| `../docker/compose.edge.yml` | Mounts edge configs + hardened container settings |
| `../helm/shinkiro/values-lab.yaml` | Lab env / labels |
| `../helm/shinkiro/values-edge.yaml` | Edge env / resources / labels |

Live firewall apply is always opt-in (`shinkiro up --apply` or `SHINKIRO_SOAR_APPLY=1`), regardless of mode.
