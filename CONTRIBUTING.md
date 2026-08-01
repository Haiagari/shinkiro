# Contributing to PromptWall

First off, thanks for taking the time to contribute! 

PromptWall is an open-source AI Security Guardrail (Firewall) designed to intercept, evaluate, and safely route prompts using a Judge LLM.

## How to Contribute
1. Fork the repository and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes.
4. Format and lint your code using standard Python tooling (`black`, `ruff`). Note: `mypy` is referenced in some docs but is not configured in this project.
5. Issue a pull request!

## Pull Request Process
1. Use the provided Pull Request template.
2. Update the README.md with details of changes to the interface, if applicable.
3. Your PR must be reviewed by at least one maintainer before merging.

## Hexagonal Architecture
We strictly adhere to a Ports and Adapters (Hexagonal) architecture. 
- `src/domain/`: Pure business logic (immutable dataclasses).
- `src/core/`: Contracts (`ITargetAPI`, `IJudgeLLM`).
- `src/adapters/`: Concrete implementations of LLM APIs and external targets.
- `src/application/`: Use cases and orchestration.
- `src/application/ports/event_bus.py`: `IEventBus` port.
- `src/adapters/llms/provider_base.py`: `AIProvider` base for LLM adapters.

Orchestration via the EventBus exists for `AIOrchestrator`, but the shipped guardrail path is the FastAPI proxy route (`POST /v1/chat/completions`) → `GuardrailDecisionService`.
Please ensure your PR respects these boundaries.
