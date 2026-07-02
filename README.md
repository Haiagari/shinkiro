# PromptWall

**AI Security Guardrail (Firewall for LLMs)**  
*Built for safe AI deployments. Engineered for reliability.*

[![Version](https://img.shields.io/badge/version-10.0.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing-22c55e?style=flat-square)](#development)
[![Python](https://img.shields.io/badge/python-3.11+-3b82f6?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-f59e0b?style=flat-square)](LICENSE)

---

## What is PromptWall

Production-ready AI Security Guardrail. Acts as a firewall for Large Language Models (LLMs), protecting your applications against prompt injections, jailbreaks, and malicious intents. 

```text
User Prompt → EventBus (Intercept) → Judge LLM (Validate) → Clean? → Target API
                                                           ↓
                                                      Block/Alert
```

**Why PromptWall instead of standard API calls:**

| Capability | PromptWall | Direct LLM Access |
|---|---|---|
| Prompt Injection Defense | Built-in | None |
| Jailbreak Prevention | Heuristic & LLM Judge | None |
| Architecture | Asynchronous EventBus | Synchronous API calls |
| Target Forwarding | Automatic routing if clean | Manual |
| Auditing | Full prompt audit trail | Manual |

## Quick Start

```bash
git clone https://github.com/SamBleed/PromptWall.git && cd PromptWall
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt && pip install -e .
python ozy.py serve --guardrail    # start the firewall
```

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Linux / macOS | Ubuntu 22.04+ |
| Python | 3.11 | 3.12+ |
| RAM | 2 GB | 4 GB |
| Network | Unrestricted outbound | — |

## Configuration

### Policy (`config/policy.yaml`)

Defines the security guardrails:

```yaml
guardrails:
  block_jailbreaks: true
  block_pii: true
  max_prompt_length: 4096
```

### Engine (`config/config.yaml`)

```yaml
threads: 50
timeout: 10

api_keys:
  judge_llm: ""      # Key for the validation LLM
  target_llm: ""     # Key for the destination LLM
```

## Architecture

Hexagonal (Ports & Adapters). Business logic has zero dependency on external tools or frameworks. The core of PromptWall relies on an asynchronous EventBus to intercept, evaluate, and route prompts.

```
Domain (Prompt Entities) ← Application (Validation Use Cases) ← Adapters (APIs)
  ↑                                                          ↑
Core (EventBus, AI Judge)                               CLI / API
```

### Flow

1. **Intercept**: The async EventBus captures incoming prompts.
2. **Validate**: A Judge LLM evaluates the prompt against prompt injections, PII leaks, and malicious intent.
3. **Action**:
   - If clean: Forwards the prompt to the Target API.
   - If malicious: Blocks the request and raises an alert.

### Project Structure

```
src/
├── domain/            # Pure business entities (Prompt, ValidationResult)
├── application/       # Use cases, prompt evaluation orchestrators
├── adapters/          # LLM integrations (Judge API, Target API)
├── core/              # Config, EventBus
├── security/          # Injection detection, PII filters
├── reporting/         # Audit logs, blocked request metrics
└── server/            # Async REST API
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
