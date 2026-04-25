# 🧠 OzyRecon

> **From Noise to Intelligence — Relationship-Driven Offensive Reconnaissance**

<div align="center">

<img src="assets/banner-ozyrecon-paradigm.png" alt="OzyRecon Banner" width="100%"/>

<br/>

[![License](https://img.shields.io/badge/license-MIT-red?style=flat-square&labelColor=0a0f1a)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/SamBleed/OzyRecon/pipeline.yml?style=flat-square&labelColor=0a0f1a)](https://github.com/SamBleed/OzyRecon/actions)
[![Python](https://img.shields.io/badge/python-3.11+-00d4ff?style=flat-square&labelColor=0a0f1a)]()

</div>

---

## ⚠️ The Problem

Traditional recon tools generate **linear, contextless noise**.

* Hundreds of findings
* Zero relationships
* Endless false positives

> The analyst becomes the filter.

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
