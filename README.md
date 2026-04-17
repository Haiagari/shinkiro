# 🚀 BugBounty Automation Framework

**Framework profesional, modular e inteligente para Bug Bounty de nivel enterprise.**

> Ejecutás un comando, te vas a tomar un café, volvés y tenés el scan listo con PoCs generados, reportes para enviar y hallazgos listos para verificar en Burp.

---

## ✨ Características Principales

| Módulo | Descripción |
|:-------|:------------|
| **🔍 Reconocimiento** | subfinder, amass, crt.sh, assetfinder en paralelo |
| **🌐 Puertos** | naabu + detección de servicios con nmap |
| **🕷️ Crawling** | waybackurls, gau, katana + fuzzing |
| **🔥 Análisis JS** | Secretos (AWS Keys, Tokens), endpoints, cambios |
| **💀 Vulnerabilidades** | Nuclei, Dalfox, Ghauri, headers, IDs detectables |
| **🎯 IDOR Detection** | Auto-detección y verificación de IDs |
| **🤖 IA + PoC Auto** | PoCs generados automáticamente (XSS, SQLi, IDOR, etc.) |
| **🧠 Fuzzing Inteligente** | Wordlists según tecnología detectada |
| **🛡️ WAF Detection** | Detecta Cloudflare, AWS WAF y ajusta estrategia |
| **🔔 Alertas Inteligentes** | Solo crítico/alto - configurabe en `config.yaml` |
| **📊 Dashboard** | Interfaz web + Timeline de evolución |
| **📈 Timeline** | Historial de cambios entre scans |
| **⏰ Scheduler 24/7** | Modo daemon, watch, diff automático |
| **📦 Export Burp** | Formato SAR - import directo en Burp Suite |
| **🌐 Auto-detectar H1** | Encuentra programas nuevos automáticamente |
| **🌍 Multi-Platform** | Reports para H1, Bugcrowd, Immunefi, OpenBB |
| **📡 Enrichment** | Shodan/Censys para enrichment de IPs |
| **🎚️ Rate Limiter** | Auto-ajusta para no romper el target |

---

## 🚀 Inicio Rápido

### 1. Instalación

```bash
cd bugbounty-framework
pip install -r requirements.txt
```

### 2. Instalar herramientas (opcional)

```bash
# Si clonaste el repo por primera vez, ejecutar setup
./setup.sh
```

Esto baixa e instala automáticamente las tools en `tools/go/bin/`.

### 3. Configurar (opcional pero recomendado)

```bash
# Editar config.yaml y agregar tus API keys
nano config.yaml
```

### 4. Un Scan

```bash
# Usando el script run.sh ( automáticamente agrega las tools al PATH)
./run.sh -t target.com --full

# O manualmente:
export PATH=$PWD/tools/go/bin:$PATH
python main.py -t target.com --full
```

### 5. Dashboard

```bash
uvicorn api:app --reload --port 8000
# Abrir http://localhost:8000
```

---

## 📋 Estructura

```
bugbounty-framework/
├── main.py              # Orquestador principal
├── api.py              # API REST + Dashboard
├── scheduler.py        # Modo 24/7
├── config.yaml         # Configuración global
├── requirements.txt   # Dependencias
│
├── modules/
│   ├── recon.py           # Recon + takeover Nuclei
│   ├── ports.py           # Escaneo de puertos
│   ├── crawler.py         # URLs + descarga JS
│   ├── vuln.py            # Vulns + IDOR detection
│   ├── js_analyzer.py     # Secretos en JS
│   ├── fuzzer.py          # Fuzzing contextual
│   ├── intelligence.py  # Scoring + CVSS
│   ├── diff.py            # Detector de cambios
│   ├── ai_analyzer.py     # PoC automático
│   ├── notifier.py       # Alertas inteligentes
│   ├── exporter.py       # Export Burp SAR
│   ├── programs_scraper.py # H1 scope
│   ├── enrichment.py      # Shodan/Censys
│   ├── waf_detector.py   # WAF detection
│   ├── rate_limiter.py  # Auto rate limit
│   ├── platforms.py     # Multi-platform reports
│   └── database.py       # SQLite
│
├── static/
│   └── index.html        # Dashboard + Timeline
│
├── scopes/              # Scopes descargados
└── output/             # Resultados
    └── {target}/
        └── {timestamp}/
            ├── recon/
            ├── ports/
            ├── urls/
            ├── vulns/
            ├── intelligence/
            ├── exporter/    # ← burp_findings.sar
            └── reports/      # ← hackerone_*.md
```

---

## 💻 Comandos

### Scan Básico
```bash
python main.py -t target.com --full
```

### Solo Recon
```bash
python main.py -t target.com --recon
```

### Con Programa H1
```bash
python main.py -t target.com -p program_name --full
```

### Scheduler 24/7
```bash
# Modo daemon (cada 6h)
python scheduler.py --daemon --diff

# Modo watch (observar un target)
python scheduler.py --watch -t target.com

# Buscar programas nuevos
python scheduler.py --h1-new
```

### Dashboard
```bash
uvicorn api:app --port 8000
# http://localhost:8000
```

---

## ⚙️ Configuración

### config.yaml

```yaml
# Rate Limiting
auto_rate_limit:
  enabled: true
  max_requests_per_min: 200

# Notificaciones (nivel mínimo)
notifications:
  alert_level: "medium"  # critical, high, medium, low, all

# API Keys
api_keys:
  shodan: "TU_KEY"
  virustotal: "TU_KEY"
  censys_id: "TU_ID"
  censys_secret: "TU_SECRET"

# IA (opcional)
ai:
  gemini_api_key: "TU_KEY"
  claude_api_key: "TU_KEY"

# Notificaciones
notifications:
  telegram_token: "TU_TOKEN"
  telegram_chat_id: "TU_CHAT_ID"
```

---

## 🎯 Ejemplo de Uso (Tu Workflow)

```bash
# 8:47am - Nuevo programa en H1
python main.py -t pagorapido.com --full

# El framework corre solo:
# → Recon (subfinder + amass + crt.sh) en paralelo
# → Detecta takeover con Nuclei
# → Puertos + URLs
# → Análisis JS (secretos + endpoints)
# → Nuclei + Dalfox + IDOR detection
# → Scoring CVSS automático
# → Genera PoCs
# → Reportes listos para H1/Bugcrowd

# 9:10am - Volvés al dashboard
# → Ver hallazgos priorizados (críticos primero)
# → Click en "📋 Copiar" del PoC
# → Importar a Burp: File → Import → burp_findings.sar

# 10:20am - Reporte enviado
# → output/target/*/reports/hackerone_1.md
# → Listo para copy-paste a H1
```

---

## 📊 Pipeline

```
┌────────────┐    ┌───────┐    ┌────────┐    ┌────────────┐
│   RECON    │───▶│ PORTS │───▶│  URLs  │───▶│ JS ANALYZ  │
│ (paralelo) │    │       │    │        │    │            │
└────────────┘    └───────┘    └────────┘    └────────────┘
     │                              │             │
     ▼                              ▼             ▼
┌──────────┐    ┌──────────┐   ┌──────────┐  ┌───────────┐
│ WAF DET  │    │  VULNS   │   │ IDOR DET │  │  FUZZER   │
│  (auto)  │    │ (Nuclei) │   │  (auto)  │  │ (context) │
└──────────┘    └──────────┘   └──────────┘  └───────────┘
     │                │             │             │
     ▼                ▼             ▼             ▼
┌───────────┐    ┌───────────┐ ┌───────────┐ ┌──────────┐
│ INTELLIG  │───▶│  AI PoC   │ │  SCORING  │ │ REPORTS  │
│(CVSS auto)│    │ (auto gen)│ │(priority) │ │ (multi)  │
└───────────┘    └───────────┘ └───────────┘ └──────────┘
     │                │                            │
     ▼                ▼                            ▼
┌──────────┐    ┌──────��─────┐             ┌─────────────┐   
│ NOTIFIER │    │  EXPORTER   │             │  DASHBOARD  │
│ (smart)  │    │ (Burp SAR ) │             │  (timeline) │
└──────────┘    └─────────────┘             └─────────────┘
```

---

## 🛠️ Herramientas Requeridas

El framework detecta automáticamente las herramientas instaladas.

| Herramienta | Para |
|------------|------|
| subfinder | Subdominios |
| httpx | Hosts vivos |
| dnsx | Resolución DNS |
| naabu | Puertos |
| nuclei | Vulnerabilidades |
| dalfox | XSS |
| katana | Crawling |
| ffuf | Fuzzing |

---

## 📈 Estado

**Versión 1.0 completada** con todas las mejoras implementadas:

- ✅ Scheduler 24/7 (--daemon, --watch, --diff)
- ✅ Export Burp SAR
- ✅ Auto-detectar programas H1
- ✅ Nuclei takeover templates
- ✅ Rate limiting automático
- ✅ Shodan/Censys enrichment
- ✅ Reports multi-platform
- ✅ Dashboard Timeline
- ✅ Auto-wordlists
- ✅ WAF detection

---

## 🤝 Contribuir

1. Fork
2. Crear branch
3. Commit
4. Push
5. Pull request

---

**Licencia:** MIT

**¿Preguntas?** Abrí un issue.
