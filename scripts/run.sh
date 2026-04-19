#!/bin/bash
# Ejecuta el BugBounty Framework con las tools locales
# Uso: ./scripts/run.sh -t target.com [--full]

# Resolver root del repositorio
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Agregar herramientas locales al PATH
TOOLS_PATH="$ROOT_DIR/tools/go/bin"
export PATH="$TOOLS_PATH:$PATH"

# Ejecutar con los argumentos originales
cd "$ROOT_DIR"

python3 backend/main.py "$@"

# Si no hay argumentos, mostrar ayuda
if [ $# -eq 0 ]; then
    echo ""
    echo "Ejemplos de uso:"
    echo "  ./scripts/run.sh -t target.com --recon"
    echo "  ./scripts/run.sh -t target.com --full"
    echo "  ./scripts/run.sh -t target.com --vulns"
fi
