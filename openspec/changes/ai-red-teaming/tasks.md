# Implementation Tasks: AI Red Teaming Orchestrator Pivot

**Delivery Strategy:** `auto-chain`
**Chain Strategy:** `stacked-to-main`

## Phase 1: Domain & Legacy Cleanup
*These tasks establish the new core data structures and remove obsolete logic.*

- [ ] **Task 1.1: Remove Legacy Adapters**
  - Delete `src/adapters/tools/nmap_adapter.py`.
  - Delete `src/adapters/tools/nuclei_adapter.py`.
  - Delete `src/adapters/tools/subfinder_adapter.py`.
  - Remove all references to these adapters in `src/adapters/tools/__init__.py`.
  - **Validation:** Ensure the codebase runs without these files. Commit as a standalone cleanup PR/Commit.

- [ ] **Task 1.2: Update Domain Models**
  - Modify `src/domain/models.py`.
  - Remove legacy models (`Asset`, `Service`, `Scan`).
  - Add `AttackPayload`, `TargetResponse`, `EvaluationResult`, `AttackPath` using `@dataclass(frozen=True)`.
  - **Validation:** Model definitions syntax check and pass type checking (e.g., `mypy`). Fix any immediate internal imports. Commit.

- [ ] **Task 1.3: Update Domain Events**
  - Modify `src/domain/events.py`.
  - Remove legacy events (e.g., `AssetDiscovered`).
  - Add `AttackAttempted`, `TargetResponded`, `GuardrailBypassed`, `AttackFailed`.
  - **Validation:** Event definitions pass type checking. Commit.

## Phase 2: Core Contracts (Ports)
*Establish the Hexagonal Architecture interfaces for the new AI domain.*

- [ ] **Task 2.1: Define Core Interfaces**
  - Modify/Create `src/core/contracts.py`.
  - Define `IAttackerLLM` with `async def generate_payload(self, context: dict, previous_responses: list) -> AttackPayload`.
  - Define `ITargetAPI` with `async def send_prompt(self, payload: AttackPayload) -> TargetResponse`.
  - Define `IJudgeLLM` with `async def evaluate_response(self, payload: AttackPayload, response: TargetResponse, criteria: dict) -> EvaluationResult`.
  - **Validation:** Interface syntax and type signatures pass `mypy`. Commit.

## Phase 3: Adapters Implementations
*Implement the concrete interfaces for external integrations.*

- [ ] **Task 3.1: Implement Attacker Adapter**
  - Create `src/adapters/llms/attacker_adapter.py`.
  - Implement the `IAttackerLLM` interface.
  - **Validation:** Passes type checking and unit tests. Commit.

- [ ] **Task 3.2: Implement Judge Adapter**
  - Create `src/adapters/llms/judge_adapter.py`.
  - Implement the `IJudgeLLM` interface.
  - **Validation:** Passes type checking and unit tests. Commit.

- [ ] **Task 3.3: Implement Target API Adapter**
  - Create `src/adapters/targets/api_adapter.py`.
  - Implement the `ITargetAPI` interface.
  - **Validation:** Passes type checking and unit tests. Commit.

## Phase 4: Application Orchestrator (Defensive Firewall Pivot)
*Wire everything together using the EventBus to act as an intercepting firewall.*

- [ ] **Task 4.1: Orchestrator Wiring & Defensive Logic**
  - Modify `src/application/orchestrator.py` (or equivalent workflow engine).
  - Remove old infrastructure scanning loops.
  - Implement the AI Security Guardrail loop:
    - Step 1: Intercept incoming prompt from user/client (simulated by a `PromptReceived` event).
    - Step 2: Use `IJudgeLLM` to evaluate the raw prompt for malicious intents, prompt injections, or jailbreaks.
    - Step 3: If Judge flags it as malicious, block it, publish `AttackBlocked`, and log the telemetry.
    - Step 4: If Judge approves it, use `ITargetAPI` to safely forward the prompt to the upstream LLM and return the response.
  - **Validation:** The defensive interception flow is unit tested and passes `pytest`. Commit.
