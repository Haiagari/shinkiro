#!/usr/bin/env bash
# Print helm upgrade --install lines for lab or edge (no cluster required).
set -euo pipefail
MODE="${1:-lab}"
if [[ "$MODE" != "lab" && "$MODE" != "edge" ]]; then
  echo "usage: $0 lab|edge" >&2
  exit 1
fi
echo "helm upgrade --install shinkiro ./deploy/helm/shinkiro \\"
echo "  --namespace security --create-namespace \\"
echo "  -f deploy/helm/shinkiro/values-${MODE}.yaml \\"
echo "  --set-file configOverride=deploy/modes/${MODE}/config.yaml \\"
echo "  --set-file playbooksOverride=deploy/modes/${MODE}/playbooks.yaml \\"
echo "  --set image.repository=shinkiro --set image.tag=local --set image.pullPolicy=IfNotPresent"
