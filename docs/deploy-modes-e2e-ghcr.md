# Lab / edge deploy modes, e2e, optional GHCR

Pointers for operators (also summarized in the root README and `deploy/README.md`).

## Deploy modes

| Mode | Command | Intent |
| --- | --- | --- |
| **lab** | `make compose-lab` | Demo mounts from `deploy/modes/lab/`; dry-run SOAR |
| **edge** | `make compose-edge` | Hardened caps / quieter playbooks; no `SHINKIRO_SOAR_APPLY` |
| Helm | `make helm-lab` / `make helm-edge` | Prints install recipes (`values-lab.yaml` / `values-edge.yaml`) |

Details: [`../deploy/modes/README.md`](../deploy/modes/README.md).

## E2E (all 15 decoys)

```bash
make e2e
# or: make e2e-shinkiro
```

Runs `scripts/e2e-shinkiro.sh` → `go test -count=1 -timeout=120s -race ./tests/e2e/`.
Registers and probes every real decoy (`ssh` … `modbus`) on high unprivileged ports (Modbus `29502`).
**No** privileged netns / `CAP_NET_BIND_SERVICE` required for this smoke.

## Optional GHCR

Set repository variable `PUSH_GHCR=true`. On `v*` tags, workflow job `push-ghcr` publishes:

- `ghcr.io/haiagari/shinkiro:<tag>`
- `ghcr.io/haiagari/shinkiro:latest`

Login uses `GITHUB_TOKEN` (`packages: write`). Binary + SBOM + Cosign release path always runs regardless.
When unset, keep using `shinkiro:local` — do not assume GHCR exists.
