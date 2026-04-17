#!/bin/bash
# Setup de herramientas de Bug Bounty Framework
# Uso: ./setup.sh

set -e

echo "🔧 BugBounty Framework - Setup de Herramientas"
echo "================================================="

# Crear directorio si no existe
mkdir -p tools/go/bin

echo "📦 Instalando herramientas de Go..."

export GOPATH=$(pwd)/tools/go
export PATH=$GOPATH/bin:$PATH
export GO111MODULE=on

#Tools a instalar
TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/projectdiscovery/dnsx/cmd/dnsx"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    "github.com/ffuf/ffuf/v2"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    "github.com/OWASP/Amass/v3/..."
    "github.com/tomnomnom/assetfinder"
    "github.com/projectdiscovery/katana/cmd/katana"
    "github.com/lc/gau/v2/cmd/gau"
    "github.com/tomnomnom/waybackurls"
)

echo "Instalando: ${#TOOLS[@]} herramientas..."

for tool in "${TOOLS[@]}"; do
    name=$(basename $tool)
    echo "  - Instalando $name..."
    go install $tool@latest 2>/dev/null || true
done

# Verificar instalación
echo ""
echo "Verificando instalación..."
INSTALLED=0

for bin in subfinder httpx dnsx naabu ffuf nuclei amass assetfinder katana gau waybackurls; do
    if [ -f "tools/go/bin/$bin" ]; then
        echo "  ✅ $bin"
        INSTALLED=$((INSTALLED+1))
    else
        echo "  ❌ $bin"
    fi
done

echo ""
echo "================================================="
if [ $INSTALLED -ge 11 ]; then
    echo "✅ INSTALACIÓN COMPLETA ($INSTALLED herramientas)"
else
    echo "⚠️ Se instalaron $INSTALLED herramientas"
fi
