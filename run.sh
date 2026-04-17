#!/bin/bash
# Ejecuta el BugBounty Framework con las tools locales
# Uso: ./run.sh -t target.com [--full]

# Agregar herramientas locales al PATH
TOOLS_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tools/go/bin"
export PATH="$TOOLS_PATH:$PATH"

# Ejecutar con los argumentos originales
cd "$(dirname "${BASH_SOURCE[0]}")"

python3 main.py "$@"

# Si no hay argumentos, mostrar ayuda
if [ $# -eq 0 ]; then
    echo ""
    echo "Ejemplos de uso:"
    echo "  ./run.sh -t target.com --recon"
    echo "  ./run.sh -t target.com --full"
    echo "  ./run.sh -t target.com --vulns"
fi