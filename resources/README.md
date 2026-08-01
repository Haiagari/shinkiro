# Resources

Shared non-code resources in the repository.

- `templates/` — v9 legacy tool configs (`config-backups.yaml`, `debug-panels.yaml`, `lfi-custom.yaml`); not consumed by current code.
- `wordlists/` — v9 legacy recon wordlists (`subdomains_massive.txt`, `subdomains.txt`, `common.txt`, `api_endpoints.txt`, `asp_files.txt`, `php_files.txt`); no current code consumes them.
- `keys/` — `api_keys.json` (KeyStore file; the active KeyStore is `config/api_keys.json`, seeded at startup) and `evidence_key.priv` (v9 evidence private key, referenced by `src/utils/crypto.py`).
- `manifests/` — empty (v9 collaboration manifests moved/removed).
- `rules/` — v9 scoring and semantic rule files (`scoring_rules.yaml`, `semantic_rules.yaml`); referenced only in SDD specs, not by shipped code.
- `visuals/` — v9 knowledge-graph visualization (`knowledge_graph_v2.html`); retained for reference.
