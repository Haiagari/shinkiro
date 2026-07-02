# Proposal: AI Red Teaming Orchestrator Pivot (PromptWall)

## Business Problem
PromptWall is pivoting from a traditional infrastructure reconnaissance framework into a modern AI Red Teaming engine. The cybersecurity industry urgently needs automated tools to test AI applications (Chatbots, RAG systems, Agents) for vulnerabilities such as Prompt Injections, Jailbreaks, and Data Exfiltration.

## Product Outcome
An asynchronous, event-driven orchestration engine that pitches a secondary "Attacker" LLM against a Target AI API. The Attacker LLM will dynamically mutate malicious prompts based on responses until a "Judge" LLM confirms that the target's guardrails have been successfully bypassed.

## Target Users
Pentesters, Red Teamers, and Security Auditors.

## Core Decisions & Business Rules
1. **Success Condition**: An independent "Judge" LLM evaluates the target's response against predefined violation criteria (e.g., "Did the target leak PII?" or "Did the target execute a malicious command?").
2. **Target Interface**: Standardized HTTP REST APIs with JSON payloads. No brittle browser automation.
3. **Deliverable**: A surgical Attack Path report detailing exactly which sequence of prompts successfully bypassed the target's security, dropping all the failed noise.
4. **Architecture Preservation**: The core Hexagonal Architecture, `AsyncEventBus`, and distributed orchestration capabilities will be retained and repurposed.

## Scope Boundaries
**In Scope (First Slice):**
- Deletion of legacy network adapters (`subfinder`, `nmap`, `nuclei`, etc.).
- Implementation of the Attacker LLM Provider.
- Implementation of the Judge LLM Provider.
- Adaptation of the domain models and events for AI interactions instead of network assets.
- Delivery of a clean, JSON-based attack report.

**Out of Scope:**
- Selenium / Playwright / UI automation.
- Deep network infrastructure reconnaissance (retired).

## Delivery Strategy
- **Mode**: `auto` (Automatic execution, no user interruption).
- **Artifact Store**: `openspec` (File-based artifacts for history and version control).
- **Delivery**: `auto-chain` (Small, chained PRs or commits to maintain reviewability without large monolithic changes).
- **Chain Strategy**: `stacked-to-main` (Sequential feature implementation).
