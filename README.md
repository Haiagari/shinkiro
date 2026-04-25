# 🧠 OzyRecon v6.0 — *Phantom Blade*

> **Advanced Offensive Reconnaissance: Invisible. Surgical. Logical.**

<div align="center">

<img src="assets/banner-ozyrecon-paradigm.png" alt="OzyRecon Banner" width="100%"/>

<br/>

[![Version](https://img.shields.io/badge/version-v6.0.0--alpha-00d4ff?style=flat-square&labelColor=0a0f1a)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-red?style=flat-square&labelColor=0a0f1a)](LICENSE)
[![Security](https://img.shields.io/badge/stealth-APT--grade-00ff88?style=flat-square&labelColor=0a0f1a)]()

</div>

---

## 🎭 v6.0 Core Pillars: "The Phantom Blade"

OzyRecon v6.0 marks a paradigm shift from traditional scanning to **Advanced Persistent Reconnaissance**.

### 1. 🧤 Advanced Stealth (The Chameleon)
Powered by `curl_cffi`, OzyRecon now bypasses modern WAFs (Cloudflare, Akamai) via **TLS Fingerprint Impersonation** and **Synthetic Identity Generation**. Your requests look like a real user, not a tool.

### 2. 🎯 Surgical Exploitation
No more noisy scans. OzyRecon uses **Evidence-Based Probing** to validate findings with minimal footprint. It only executes precise payloads when the relationship-logic confirms a high probability of success.

### 3. 🔍 Logic-Bug Pattern Matching
Leveraging the **Knowledge Graph**, the v6.0 Engine correlates data across isolated assets to discover complex logical attack paths (e.g., cross-asset IDORs, credential leakage bridges).

---

## 🧠 The Shift: Graph-First Intelligence

OzyRecon doesn’t scan targets — it builds **relationships**.

* Assets become **nodes**
* Connections become **edges**
* Weak signals become **Attack Paths**

<div align="center">
  <img src="assets/knowledge-graph-v5.png" alt="Knowledge Graph Visualization" width="900">
  <br>
  <sub><i>Knowledge Graph correlating infrastructure into actionable attack paths.</i></sub>
</div>

---

## 🔥 Why OzyRecon is Different

### 🧩 Correlation Engine (Not Just Detection)

Findings are **validated through relationships**, not isolated signals.

→ Open port ≠ vulnerability
→ Correlated evidence = **Critical Attack Vector**

---

### 📉 26x Noise Reduction

Evidence-based scoring eliminates irrelevant data.

* No correlation → ignored
* Multi-signal validation → escalated

---

### 🧑‍💻 Human-in-the-Loop Security

No blind exploitation.

```text
Attack Hypothesis → PENDING_APPROVAL → Controlled Execution
```

You decide **when** and **what** runs.

---

### 🔐 Cryptographic Evidence Layer

Every finding is:

* Hashed (SHA256)
* Timestamped
* Audit-ready

Built for **compliance, trust, and reproducibility**.

---

## ⚙️ Architecture Snapshot

| Layer         | Stack                            |
| ------------- | -------------------------------- |
| Core          | Python 3.11 (strict typing)      |
| Visualization | Jinja2 + D3.js                   |
| Security      | Bandit (SAST)                    |
| Storage       | Volatile + Persistent separation |
| Engine        | Graph-Based Inference            |

---

## ⚡ Quick Start

```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
./setup.sh
./ozy.py
```

---

## 📚 Documentation

* 📦 [Installation](docs/INSTALL.md)
* 🧪 [Use Cases](docs/USE_CASES.md)
* 📊 [Benchmarks](docs/BENCHMARKS.md)
* 🛣️ [Roadmap](docs/ROADMAP.md)
* 🤝 [Contributing](CONTRIBUTING.md)

---

<div align="center">

**Built for operators who prefer signal over noise.**

</div>
