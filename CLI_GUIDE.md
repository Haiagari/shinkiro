# OzyRecon CLI Guide

Unified CLI para operaciones de reconocimiento persistente avanzadas.

## Installation

### Desde el proyecto
```bash
cd /path/to/OzyRecon
pip install -e .
```

### Uso directo
```bash
./ozy <command> [OPTIONS] [ARGS]...
# o desde Python
python -m cli.ozy <command> [OPTIONS] [ARGS]...
```

## Global Options

| Option | Description |
|--------|-------------|
| `--debug` | Habilita logging verbose y output detallado |
| `--config PATH` | Especifica un archivo de configuración personalizado |
| `--version` | Muestra información de versión |
| `--help` | Muestra este mensaje de ayuda |

## Modos de Operación

### hunt
Reconocimiento básico de objetivos.
```bash
ozy hunt <target> [OPTIONS]
```

### continuous
Reconocimiento continuo con monitorización.
```bash
ozy continuous <target> [OPTIONS]
```

### campaign
Operación de campaña coordinada.
```bash
ozy campaign <target> [OPTIONS]
```

### research
Investigación profunda y análisis.
```bash
ozy research <target> [OPTIONS]
```

### forensic
Análisis forense de activos.
```bash
ozy forensic <target> [OPTIONS]
```

### service
Enumeración de servicios.
```bash
ozy service <target> [OPTIONS]
```

## Opciones por Modo

| Option | Description | Default |
|--------|-------------|---------|
| `--threads N` | Número de threads paralelos | Auto |
| `--speed` | Velocidad: slow, normal, fast | normal |
| `--depth` | Profundidad: shallow, standard, deep | standard |

## Configuration

El archivo de configuración por defecto se busca en:
1. `--config` path dado
2. `~/.ozyrecon/config.yaml`
3. `./config.yaml`

## Ejemplos

```bash
# Ver help
ozy --help

# Ver versión
ozy --version

# Ejecutar hunt básico
ozy hunt example.com

# Modo debug
ozy --debug hunt example.com

# Con opciones personalizadas
ozy hunt example.com --threads 50 --speed fast --depth deep
```

## Logging

- **Modo normal**: Output limpio sin información sensible
- **Modo debug** (`--debug`): Muestra tracebacks completos y logs detallados

## Signal Handling

La CLI maneja SIGINT (Ctrl+C) y SIGTERM para shutdown limpio, guardando estado antes de salir.

## OPSEC Considerations

- No se loguea información sensible en salida estándar
- En modo debug, traces solo visibles para desarrollo
- Config y credenciales nunca se exponen en output