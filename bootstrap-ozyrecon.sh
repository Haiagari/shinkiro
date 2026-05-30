#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
REPO_URL=""
CLONE_DIR="${CLONE_DIR:-OzyRecon}"
YES_ARGS=()

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BLUE=$'\033[34m'
RESET=$'\033[0m'

info() { printf '%b\n' "${BLUE}[i]${RESET} $*"; }
ok() { printf '%b\n' "${GREEN}[✓]${RESET} $*"; }
warn() { printf '%b\n' "${YELLOW}[!]${RESET} $*"; }
die() { printf '%b\n' "${RED}[x]${RESET} $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  bash bootstrap-ozyrecon.sh --repo-url <git-url> [--clone-dir name] [--yes ...]

Examples:
  curl -fsSL <RAW_URL>/bootstrap-ozyrecon.sh | bash -s -- --repo-url https://github.com/org/OzyRecon.git --target example.com --tests
  bash bootstrap-ozyrecon.sh --repo-url git@github.com:org/OzyRecon.git --clone-dir OzyRecon-dev --yes --import-only

Purpose:
  - clone the repo if needed
  - delegate to scripts/try-ozyrecon.sh inside the cloned repo
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo-url)
        REPO_URL="${2:-}"
        shift
        ;;
      --clone-dir)
        CLONE_DIR="${2:-}"
        shift
        ;;
      --yes|--target|--scope-file|--import-only|--tests)
        YES_ARGS+=("$1")
        if [[ "$1" == "--target" || "$1" == "--scope-file" ]]; then
          YES_ARGS+=("${2:-}")
          shift
        fi
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
  done
}

ensure_python() {
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python not found: $PYTHON_BIN"
}

main() {
  parse_args "$@"
  ensure_python

  local repo_root="$ROOT_DIR"
  if [[ ! -f "$ROOT_DIR/pyproject.toml" ]]; then
    [[ -n "$REPO_URL" ]] || die "Pass --repo-url when running outside a cloned repo."
    repo_root="$(mktemp -d)"
    info "Cloning $REPO_URL into $repo_root/$CLONE_DIR..."
    git clone "$REPO_URL" "$repo_root/$CLONE_DIR"
    repo_root="$repo_root/$CLONE_DIR"
  elif [[ -n "$REPO_URL" ]]; then
    warn "--repo-url ignored because you're already inside a cloned repo."
  fi

  [[ -x "$repo_root/scripts/try-ozyrecon.sh" ]] || chmod +x "$repo_root/scripts/try-ozyrecon.sh"
  ok "Bootstrap target ready at $repo_root"
  info "Delegating to local helper..."
  (cd "$repo_root" && bash scripts/try-ozyrecon.sh "${YES_ARGS[@]}")
}

main "$@"
