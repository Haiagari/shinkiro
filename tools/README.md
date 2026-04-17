# 🛠️ Herramientas GO Locales

Este directorio contiene las herramientas de seguridad Installed de forma local, sin contaminar tu sistema.

## ¿Por qué aquí?

Las herramientas de ProjectDiscovery (subfinder, httpx, nuclei, etc.) se Instalan tradicionalmente con `go install` Globally, lo que las mete en `$GOPATH/bin` o `$HOME/go/bin`.

Al Instalar aquí:
- ✅ **No ensuician tu sistema**
- ✅ **Fáciles de eliminar** (borrar esta carpeta)
- ✅ **Portables** (podes llevar la carpeta a otra máquina)

## Herramientas Incluidas

| Herramienta | Para qué | Tamaño |
|------------|---------|--------|
| **subfinder** | Subdominios (pasivo) | 45MB |
| **httpx** | Hosts vivos + Tech | 74MB |
| **dnsx** | Resolución DNS | 44MB |
| **naabu** | Escaneo de puertos | 46MB |
| **ffuf** | Fuzzing web | 14MB |
| **nuclei** | Vulns (templates) | 168MB |

## Cómo usarlas

### Opción 1: Agregar al PATH solo para esta sesión

```bash
export PATH=$PWD/tools/go/bin:$PATH

# Ejemplo:
subfinder -d example.com -silent
httpx -list urls.txt -silent
```

### Opción 2: Agregar permanentemente (bash/zsh)

Agregar al `~/.bashrc` o `~/.zshrc`:

```bash
export PATH="/ruta/a/bugbounty-framework/tools/go/bin:$PATH"
```

Luego:
```bash
source ~/.bashrc  # o source ~/.zshrc
subfinder -d target.com
```

### Opción 3: Desde el código Python

El framework自动 detecta las tools en esta carpeta si están en el PATH.

## Cómo Instalar más tools

Si necesitás más tools de Go:

```bash
export GOPATH=$(pwd)/tools/go
export PATH=$GOPATH/bin:$PATH
export GO111MODULE=on

# Ejemplo: agregar amass
go install github.com/owasp/amass/v4/cmd/amass@latest

# O katana
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Para qué sirve cada tool

- **subfinder**: Encuentra subdominios usando fuentes pasivas (no tocá el target)
- **httpx**: Detecta hosts vivos, tecnología, status codes
- **dnsx**: Resuelve DNS rápido
- **naabu**: Escanea puertos rápido
- **nuclei**: Escanea vulnerabilidades usando templates
- **ffuf**: Fuzzing web (directorios, parámetros)

## Notas

- Las tools están compiladas para tu arquitectura (x86_64 Linux)
- Nuclei necesita descargar templates: `nuclei -update-templates`
- Algunas tools usan API keys opcionales (ver `config.yaml`)
- Si una tool no está, el framework usa fallback (ej: crt.sh)

## Links

- [ProjectDiscovery](https://github.com/projectdiscovery)
- [Chaos Client](https://github.com/projectdiscovery/chaos-client)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)