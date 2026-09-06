#!/usr/bin/env bash
# Shinkiro e2e smoke — exercises all 15 real decoys via tests/e2e.
#
# Privileges: none required. Listeners bind high ephemeral ports (29xxx),
# including Modbus on 29502 instead of privileged :502.
# No network namespaces, Docker, or CAP_NET_ADMIN needed.
#
# Usage:
#   ./scripts/e2e-shinkiro.sh
#   make e2e
#   make e2e-shinkiro

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Shinkiro e2e (15 decoys, unprivileged high ports)"
echo "    package: ./tests/e2e"
echo "    privileges: none (no netns / CAP_NET_BIND_SERVICE)"
echo

go test -count=1 -timeout=120s -race ./tests/e2e/

echo
echo "==> e2e OK — all registered decoys probed"
