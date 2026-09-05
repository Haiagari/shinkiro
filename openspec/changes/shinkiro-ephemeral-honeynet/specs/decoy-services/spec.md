# Decoy Services Specification

## Purpose
In-memory protocol emulators designed to deceive reconnaissance bots and human attackers into disclosing their payloads and tools without touching real host systems.

## Requirements

### Requirement: DECOY-SSH-1 — Interactive SSH Honeypot
The SSH decoy MUST emulate OpenSSH banner exchange, credential acquisition, and provide an in-memory virtual terminal session.

#### Scenario: Attacker attempts brute-force login
- GIVEN an active connection to the SSH port
- WHEN the client sends credentials (`root`/`password123`)
- THEN the decoy captures the credentials in telemetry
- AND grants access to a synthetic in-memory shell prompt

#### Scenario: Attacker executes recon commands in synthetic shell
- GIVEN an authenticated session in the synthetic shell
- WHEN the attacker runs `uname -a`, `whoami`, or `cat /etc/passwd`
- THEN the decoy returns realistic synthetic outputs
- AND records each keystroke and command into the session telemetry

### Requirement: DECOY-REDIS-1 — RESP Protocol Emulator
The Redis decoy MUST respond to standard RESP commands (`PING`, `INFO`, `SET`, `GET`, `CONFIG`, `EVAL`).

#### Scenario: Attacker checks unauthenticated Redis instance
- GIVEN a connection on Redis port (6379)
- WHEN the client issues `INFO`
- THEN the decoy returns realistic Redis 7.x server info
- AND flags the IP for active database reconnaissance

#### Scenario: Rogue Lua Script Injection
- GIVEN an attacker executing `EVAL` with malicious Lua code
- WHEN the command is received
- THEN the payload is intercepted, hashed with SHA-256, and stored as an IoC without executing on the host

### Requirement: DECOY-DOCKER-1 — Docker API Emulator
The Docker decoy MUST emulate Docker daemon REST endpoints (`/_ping`, `/version`, `/v1.24/containers/create`).

#### Scenario: Crypto-miner container creation probe
- GIVEN a client calling `POST /v1.24/containers/create` with an image like `xmrig/xmrig`
- WHEN the request body is parsed
- THEN the decoy simulates a fake container creation response
- AND flags the target container image and command arguments as high-severity IoCs
