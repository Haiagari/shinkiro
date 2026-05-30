# Tools

Local copies of the Go-based discovery tools used by OzyRecon.

## Purpose

- keep tooling isolated from the host system
- make the runtime portable
- allow the CLI to resolve binaries deterministically

## Common tools

- `subfinder`
- `httpx`
- `dnsx`
- `naabu`
- `ffuf`
- `nuclei`

## Notes

- tools are resolved through the CLI/runtime path resolver
- missing tools degrade features instead of breaking the engine
