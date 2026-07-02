# Technical Specifications: AI Red Teaming Orchestrator Pivot

## Executive Summary
This document outlines the technical specifications for pivoting OzyRecon from a traditional infrastructure reconnaissance framework into a modern AI Red Teaming engine. The core event-driven architecture will be preserved, but domain models, events, and adapters will be re-aligned toward AI interactions (Attacker, Target, Judge).

## 1. Domain Models (`src/domain/models.py`)
The existing models (e.g., `Asset`, `Service`, `Scan`) will be replaced or supplemented by AI-focused entities. All models must remain immutable (`@dataclass(frozen=True)`).

* **`AttackPayload`**: Represents a mutated prompt designed to test the target.
  * Fields: `id: str`, `session_id: str`, `content: str`, `strategy: str` (e.g., "prompt_injection", "jailbreak"), `timestamp: datetime`

* **`TargetResponse`**: The raw output returned by the Target API after receiving an `AttackPayload`.
  * Fields: `id: str`, `payload_id: str`, `content: str`, `status_code: int`, `latency_ms: int`, `timestamp: datetime`

* **`EvaluationResult`**: The verdict delivered by the Judge LLM on whether a `TargetResponse` violated safety criteria.
  * Fields: `id: str`, `response_id: str`, `is_bypassed: bool`, `violation_type: str`, `judge_reasoning: str`, `severity: str`

* **`AttackPath`**: The sequence of prompts that successfully achieved a bypass.
  * Fields: `id: str`, `target: str`, `successful_payloads: List[AttackPayload]`, `final_evaluation: EvaluationResult`

## 2. Domain Events (`src/domain/events.py`)
Events will drive the asynchronous orchestration via `src/events/bus.py`.

* **`AttackAttempted`**: Fired when an `AttackPayload` is sent to the Target API.
  * Payload: `AttackPayload`
* **`TargetResponded`**: Fired when the Target API replies.
  * Payload: `TargetResponse`
* **`GuardrailBypassed`**: Fired when the Judge LLM confirms a successful attack.
  * Payload: `EvaluationResult`
* **`AttackFailed`**: Fired when the Judge LLM determines the target's guardrails held.
  * Payload: `EvaluationResult`

## 3. Interfaces / Ports (`src/core/contracts.py` or similar)
Strict Hexagonal Architecture dictates that business logic must not depend on concrete implementations.

* **`IAttackerLLM`**
  * `async def generate_payload(self, context: dict, previous_responses: list) -> AttackPayload`
* **`ITargetAPI`**
  * `async def send_prompt(self, payload: AttackPayload) -> TargetResponse`
* **`IJudgeLLM`**
  * `async def evaluate_response(self, payload: AttackPayload, response: TargetResponse, criteria: dict) -> EvaluationResult`

## 4. Legacy Removals
The following files, directories, and capabilities related to traditional network reconnaissance will be completely deleted:
* `src/adapters/tools/nmap_adapter.py`
* `src/adapters/tools/nuclei_adapter.py`
* `src/adapters/tools/subfinder_adapter.py`
* References to these tools in `src/adapters/tools/__init__.py`.
* Obsolete models in `src/domain/models.py` (`Asset`, `Service`, etc.).
* Obsolete events in `src/domain/events.py` (`AssetDiscovered`, etc.).

## 5. Sequence / Flow
1. The Orchestrator initiates an attack session via `IAttackerLLM`.
2. The Attacker generates an `AttackPayload`. Event `AttackAttempted` is published.
3. The engine uses `ITargetAPI` to deliver the payload. Once received, `TargetResponded` is published.
4. The `EventBus` triggers the Judge workflow. `IJudgeLLM` evaluates the response.
5. If successful, `GuardrailBypassed` is published and the `AttackPath` report is compiled.
6. If failed, `AttackFailed` is published, which triggers the Attacker LLM to mutate the prompt and try again.
