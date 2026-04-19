#!/bin/bash
# Mantiene solo las N ejecuciones más recientes por target dentro de runtime/scans/

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANS_DIR="$ROOT_DIR/runtime/scans"
KEEP_PER_TARGET="${1:-5}"

if ! [[ "$KEEP_PER_TARGET" =~ ^[0-9]+$ ]]; then
    echo "Uso: ./scripts/prune_scans.sh [cantidad_a_conservar]"
    exit 1
fi

if [ ! -d "$SCANS_DIR" ]; then
    echo "[*] No existe $SCANS_DIR, nada para podar."
    exit 0
fi

echo "[*] Conservando las últimas $KEEP_PER_TARGET ejecuciones por target..."

shopt -s nullglob
for target_dir in "$SCANS_DIR"/*; do
    [ -d "$target_dir" ] || continue

    mapfile -t sessions < <(find "$target_dir" -mindepth 1 -maxdepth 1 -type d | sort -r)
    if [ "${#sessions[@]}" -le "$KEEP_PER_TARGET" ]; then
        continue
    fi

    for old_session in "${sessions[@]:$KEEP_PER_TARGET}"; do
        echo "  - Eliminando $old_session"
        rm -rf "$old_session"
    done
done

echo "[+] Poda completada."
