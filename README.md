# PromptWall

**AI Security Guardrail (Firewall for LLMs)**  
*Built for safe AI deployments. Engineered for reliability.*

[![Version](https://img.shields.io/badge/version-0.1.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing-22c55e?style=flat-square)](#development)
[![Python](https://img.shields.io/badge/python-3.11+-3b82f6?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-f59e0b?style=flat-square)](LICENSE)

---

## What is PromptWall

Production-ready AI Security Guardrail. Acts as a firewall for Large Language Models (LLMs), protecting your applications against prompt injections, jailbreaks, and malicious intents. PromptWall exposes an OpenAI-compatible proxy that validates every request against a Judge LLM before forwarding it upstream.

```text
Client (OpenAI-compatible) → Guardrail Proxy (Bearer auth, rate limit) → Judge LLM (safe?)
                                                                              ↓
                                                              Allowed → Upstream passthrough / SSE
                                                              Blocked → 403 / 429
```

**Why PromptWall instead of standard API calls:**

| Capability | PromptWall | Direct LLM Access |
|---|---|---|
| Prompt Injection Defense | Built-in | None |
| Jailbreak Prevention | Heuristic & LLM Judge | None |
| Architecture | Guarded OpenAI-compatible proxy | Synchronous API calls |
| Target Forwarding | Automatic routing if clean | Manual |
| Auditing | Full prompt audit trail | Manual |

## Quick Start

```bash
git clone https://github.com/Haiagari/PromptWall.git && cd PromptWall
python -m venv venv && source venv/bin/activate
pip install -e .
python ozy.py serve    # start the firewall (boots the whole proxy)
```

Set the required API keys before starting: `PROMPTWALL_JUDGE_API_KEY` (Judge LLM) and `PROMPTWALL_UPSTREAM_API_KEY` (upstream), and seed an API key via `ozy keys create`.

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Linux / macOS | Ubuntu 22.04+ |
| Python | 3.11 | 3.12+ |
| RAM | 2 GB | 4 GB |
| Network | Unrestricted outbound | — |

## Configuration

The guardrail proxy is configured via `config/config.yaml`:

```yaml
guardrail:
  fail_open: false  # MUST default closed (AD-8)
  judge:
    base_url: "https://api.openai.com/v1"   # REQUIRED (JUDGE-1, fails startup if empty)
    model: "gpt-4o-mini"                    # REQUIRED (JUDGE-1)
    api_key_env: "PROMPTWALL_JUDGE_API_KEY"
    timeout_seconds: 10
    retries: 2
  upstream:
    base_url: "https://api.openai.com/v1"
    api_key_env: "PROMPTWALL_UPSTREAM_API_KEY"
  audit:
    path: "runs/audit_guardrail.jsonl"
```

Judge and upstream credentials are read from environment variables (`PROMPTWALL_JUDGE_API_KEY`, `PROMPTWALL_UPSTREAM_API_KEY`) — never from config files.

## API

- `POST /v1/chat/completions` — OpenAI-compatible guarded proxy. Accepts `model`, `messages`, `stream`, `temperature`. Authentication via `Authorization: Bearer <key>` (see `ozy keys create`).
- `GET /` — service metadata (name + version).
- `GET /health` — liveness probe.

Errors follow the shape `{"error": {code, reason, message, ...}}` with HTTP status codes `401` (missing/invalid key), `403` (insufficient scope), `429` (rate limit), `422` (validation), `502` (upstream failure).

## Architecture

Hexagonal (Ports & Adapters). Business logic has zero dependency on external tools or frameworks.

```
Domain (Prompt Entities) ← Application (GuardrailDecisionService) ← Adapters (LLM judge, upstream)
  ↑                                                                             ↑
Core (Config, Contracts)                                                   CLI / FastAPI
```

### Flow

1. **Authenticate**: `POST /v1/chat/completions` validates the `Bearer` token against the KeyStore (`config/api_keys.json`, sha256-hashed keys).
2. **Authorize**: The request scope is checked; a key without the `chat` scope is rejected with `403`.
3. **Rate limit**: A per-key fixed-window limiter rejects excess requests with `429` + `Retry-After`.
4. **Validate**: `GuardrailDecisionService` sends the prompt to the Judge LLM (fail-closed: only an explicit `safe` verdict forwards).
5. **Forward**: Clean requests pass through upstream (non-stream) or are relayed as SSE (`stream: true`).

An `IEventBus` exists for `AIOrchestrator` usage, but the shipped guardrail path is the direct FastAPI proxy route above.

### Project Structure

```
src/
├── domain/            # Pure business entities (Prompt, ValidationResult)
├── application/       # GuardrailDecisionService, orchestrator, ports
├── adapters/          # LLM integrations (judge provider, upstream API)
├── core/              # Config, contracts, bootstrap, errors
├── auth/              # KeyStore, rate limiting, audit
├── notifications/     # Alerting (Telegram, notifier)
├── plugins/           # Plugin base, loader, hooks
├── storage/           # Database access
└── utils/             # Crypto and shared helpers
```

## Development

```bash
source venv/bin/activate
pytest                    
ruff check src/ tests/    # lint
```

---

**License**: MIT  
**Use responsibly.**
