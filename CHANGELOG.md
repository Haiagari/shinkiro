# Changelog

## [0.1.0] - 2026-08-01

Initial consolidated release of PromptWall as an AI Security Guardrail (firewall for LLMs). Supersedes the legacy 9.x recon-platform versioning, which was dropped as incorrect for the current product.

### Added
- **Guarded OpenAI-compatible proxy route**: `POST /v1/chat/completions` with KeyStore Bearer auth (sha256-hashed keys in `config/api_keys.json`, per-key scopes + rate limits). Requests without the `chat` scope return `insufficient_scope` 403; per-key fixed-window rate limit returns 429 with `Retry-After`.
- **JSONL audit trail**: `runs/audit_guardrail.jsonl` recording `decision_id`, `key_name`, `outcome`, `reason_code`, `prompt_hash`, and `confidence`.
- **OpenAI-compatible judge adapter**: retries and fail-closed verdict parsing — only an explicit `safe` verdict forwards; anything else is blocked or treated as `judge_unavailable`.
- **Upstream passthrough**: non-stream requests are forwarded as-is; `stream: true` is relayed as SSE; upstream failures return 502.
- **Judge LLM Validator**: evaluation layers that detect prompt injections, jailbreaks, and malicious intents.
- **Safe Forwarding**: routes clean prompts to Target APIs while blocking malicious ones.
- **CLI**: `serve` (`--host`/`--port`), `keys create` / `keys list` / `keys revoke`, and `self-test`.

### Changed
- **Massive Architectural Pivot**: PromptWall transitioned from an Offensive Infrastructure Recon tool to an AI Security Guardrail.
- **Core Engine**: replaced linear scanning engines with an asynchronous EventBus designed to intercept and validate incoming prompts.

### Removed
- **Legacy Recon Tools**: removed network scanning tools (`nmap`, `subfinder`, `nuclei`, `httpx`, `naabu`, etc.), offensive discovery phases, and recon modes (hunt, continuous, research, campaign, forensic).
