#!/bin/bash
# Verifica que la estructura del repo siga el layout esperado.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "[-] $1"
    exit 1
}

require_dir() {
    [ -d "$1" ] || fail "Falta el directorio requerido: $1"
}

require_file() {
    [ -f "$1" ] || fail "Falta el archivo requerido: $1"
}

require_dir "$ROOT_DIR/backend"
require_dir "$ROOT_DIR/config"
require_dir "$ROOT_DIR/cli"
require_dir "$ROOT_DIR/docs"
require_dir "$ROOT_DIR/resources"
require_dir "$ROOT_DIR/runtime"
require_dir "$ROOT_DIR/scripts"
require_dir "$ROOT_DIR/tests"
require_dir "$ROOT_DIR/ui"

require_file "$ROOT_DIR/agent.py"

require_dir "$ROOT_DIR/src"
require_dir "$ROOT_DIR/src/core"
require_dir "$ROOT_DIR/src/opsec"
require_dir "$ROOT_DIR/src/discovery"
require_dir "$ROOT_DIR/src/scanners"
require_dir "$ROOT_DIR/src/storage"
require_dir "$ROOT_DIR/src/intelligence"
require_dir "$ROOT_DIR/src/notifications"
require_dir "$ROOT_DIR/src/export"
require_dir "$ROOT_DIR/src/modes"

require_dir "$ROOT_DIR/runtime/db"
require_dir "$ROOT_DIR/runtime/logs"
require_dir "$ROOT_DIR/runtime/scans"
require_dir "$ROOT_DIR/runtime/state"

require_file "$ROOT_DIR/runtime/db/ozyrecon.db"
require_file "$ROOT_DIR/runtime/logs/agent_reasoning.log"
require_file "$ROOT_DIR/runtime/state/llm_usage.json"

if [ -d "$ROOT_DIR/scopes" ]; then
    fail "La carpeta scopes/ ya no debería existir"
fi

shopt -s nullglob
for target_dir in "$ROOT_DIR/runtime/scans"/*; do
    [ -d "$target_dir" ] || continue
    for session_dir in "$target_dir"/*; do
        [ -d "$session_dir" ] || continue
        session_name="$(basename "$session_dir")"
        if ! [[ "$session_name" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
            fail "Sesión inválida en runtime/scans: $session_dir"
        fi
    done
done

echo "[+] Estructura verificada correctamente."
