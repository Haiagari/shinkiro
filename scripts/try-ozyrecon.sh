#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
YES_MODE=false
TARGET=""
SCOPE_FILE=""
IMPORT_ONLY=false
RUN_TESTS=false

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
  bash scripts/try-ozyrecon.sh [--yes] [--target domain] [--scope-file file] [--import-only] [--tests]

What it does:
  - creates/uses a virtualenv
  - installs dev dependencies
  - runs ozy doctor
  - runs ozy init
  - manages scope in batch
  - optionally runs flow and pytest

Behavior:
  - `--target` is the only flag that triggers `flow`
  - scope import happens only when `--scope-file` or `--import-only` is used

This helper is LOCAL-ONLY: run it from inside an already cloned OzyRecon repo.
If you need to clone first, use `bootstrap-ozyrecon.sh`.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes) YES_MODE=true ;;
      --target)
        TARGET="${2:-}"
        shift
        ;;
      --scope-file)
        SCOPE_FILE="${2:-}"
        shift
        ;;
      --import-only) IMPORT_ONLY=true ;;
      --tests) RUN_TESTS=true ;;
      -h|--help)
        usage
        exit 0
        ;;
      --repo-url|--clone-dir)
        die "This helper is local-only. Use bootstrap-ozyrecon.sh for clone/bootstrap flows."
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
  done
}

confirm() {
  local prompt="$1"
  $YES_MODE && return 0
  read -r -p "$prompt [y/N]: " answer
  [[ "${answer:-}" =~ ^[Yy]$ ]]
}

ensure_python() {
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "Python not found: $PYTHON_BIN"
}

setup_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  python -m pip install --upgrade pip >/dev/null
  [[ -f "$ROOT_DIR/pyproject.toml" ]] || die "pyproject.toml not found in $ROOT_DIR"
  info "Installing editable dev dependencies..."
  (cd "$ROOT_DIR" && pip install -e ".[dev]")
  ok "Environment ready"
}

run_cli() {
  (cd "$ROOT_DIR" && python ozy.py "$@")
}

import_default_targets() {
  local default_targets="$ROOT_DIR/scripts/targets.example.txt"
  local source_file="${SCOPE_FILE:-$default_targets}"

  if [[ -f "$source_file" ]]; then
    info "Importing scope from $source_file..."
    run_cli scope import "$source_file"
  else
    warn "No scope file provided and no default template found at $default_targets"
  fi
}

main() {
  parse_args "$@"

  ensure_python
  setup_venv

  info "Running doctor..."
  run_cli doctor

  info "Running init..."
  run_cli init

  if $YES_MODE; then
    if $IMPORT_ONLY || [[ -n "$SCOPE_FILE" ]]; then
      import_default_targets
      if $IMPORT_ONLY; then
        ok "Scope imported."
        exit 0
      fi
    fi
    if [[ -n "$TARGET" ]]; then
      info "Running flow for $TARGET..."
      run_cli flow "$TARGET"
    else
      info "No target passed, so flow was skipped."
    fi
    if $RUN_TESTS; then
      (cd "$ROOT_DIR" && python -m pytest)
    fi
    ok "Done."
    exit 0
  fi

  if confirm "Do you want to manage scope now?"; then
    read -r -p "Enter domains separated by spaces (e.g. example.com *.example.com): " scope_input
    if [[ -n "${scope_input// }" ]]; then
      # shellcheck disable=SC2086
      run_cli scope add $scope_input
    fi

    if confirm "Import more targets from a file?"; then
      read -r -p "Path to targets file: " targets_file
      [[ -f "$targets_file" ]] || die "Targets file not found: $targets_file"
      run_cli scope import "$targets_file"
    fi

    run_cli scope list
  fi

  if confirm "Run a scoped flow now?"; then
    read -r -p "Target to test (must be authorized and in scope): " target
    [[ -n "$target" ]] || die "Target cannot be empty"
    run_cli flow "$target"
  fi

  if confirm "Run the full test suite?"; then
    (cd "$ROOT_DIR" && python -m pytest)
  fi

  ok "Done. If you want a repeatable target list, use: python ozy.py scope import targets.txt"
}

main "$@"
