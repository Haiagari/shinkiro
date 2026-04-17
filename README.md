# 🚀 BugBounty Automation Framework v2.0

**Plataforma profesional, modular e inteligente para Reconocimiento y Escaneo de Vulnerabilidades.**

Este framework no es solo una colección de herramientas; es una **infraestructura de Bug Bounty** diseñada para automatizar la intuición del hunter y escalar operaciones sin ser detectado.

---

## 🏛️ Los 4 Pilares Profesionales (Metodología de Elite)

Hemos profesionalizado el framework bajo 4 pilares críticos para el éxito en programas modernos:

### 1. 💾 Persistencia Inteligente (SQLite + SQLAlchemy)
Se acabó el depender de archivos JSON volátiles. 
- **Memoria Real:** Base de datos persistente que guarda cada host, puerto y hallazgo con timestamp.
- **Motor de Diferencias (SQL-based):** Detecta automáticamente qué cambió entre scans. ¿Apareció un puerto nuevo? ¿Un subdominio nuevo? El framework lo sabe.
- **Consultas Rápidas:** Índices optimizados para buscar vulnerabilidades críticas a través de miles de registros en milisegundos.

### 2. 🔔 Notificaciones de Alta Señal (Telegram Smart Alerts)
No queremos spam, queremos acción.
- **Filtrado por Severidad:** Recibí alertas inmediatas en tu celular para hallazgos **CRITICAL**, **HIGH** y **MEDIUM**.
- **Reportes de Novedades:** Resúmenes automáticos al finalizar cada scan detallando nuevos descubrimientos (Diff Engine).
- **Conectividad Total:** Integración nativa con bots de Telegram.

### 3. 🥷 OPSEC & Sigilo Avanzado (Ninja Mode)
Entrá sin hacer ruido. Evitá los baneos de IP de los Firewalls corporativos.
- **Rotación de Identidades:** Cambio dinámico de User-Agents reales (Chrome, Firefox, Safari) en cada request.
- **Jitter Aleatorio:** Retrasos variables entre peticiones para imitar comportamiento humano.
- **Kill-Switch de Emergencia:** Si detectamos un baneo masivo (múltiples 403/429), el framework frena en seco para proteger tu infraestructura.
- **Detección de WAF Adaptativa:** Identifica Cloudflare, AWS WAF, Akamai, etc., y ajusta automáticamente la agresividad del scan.

### 4. 🧠 Estrategia de Detección Propia (Custom Templates)
No corras lo que corren todos.
- **Custom Templates Directory:** Carpeta dedicada para tus propias firmas de Nuclei.
- **Detección Diferencial:** Buscamos archivos de backup (.bak, .swp), paneles de debug expuestos y patrones de LFI/IDOR personalizados que las herramientas estándar ignoran.

---

## ✨ Características Técnicas

| Módulo | Descripción |
|:-------|:------------|
| **🔍 Recon + Fallback** | Subfinder, crt.sh y fallback automático al target base si no hay subdominios. |
| **🌐 Puertos & Services** | Naabu + Nmap con inyección automática en el PATH. |
| **💀 Vulnerabilidades** | Nuclei con integración de Custom Templates + Dalfox + SQLmap/Ghauri. |
| **🎯 Smart Fuzzing** | Wordlists contextuales según la tecnología detectada en el target. |
| **📈 DB Queries** | 9 funciones de helper para extraer inteligencia de la base de datos. |
| **📦 Multi-Platform** | Generación de reportes listos para HackerOne, Bugcrowd e Immunefi. |

---

## 🚀 Inicio Rápido

### 1. Instalación
```bash
git clone https://github.com/SamBleed/bugbounty-framework
cd bugbounty-framework
pip install -r requirements.txt
./setup.sh  # Descarga tools locales en tools/go/bin
```

### 2. Configuración (Crucial)
Edita `config.yaml` para habilitar el sigilo y las notificaciones:
```yaml
notifications:
  telegram_token: "TU_TOKEN"
  telegram_chat_id: "TU_ID"
```

### 3. Ejecución
El framework ahora gestiona automáticamente las herramientas de Go. No necesitas configurar el PATH manualmente.
```bash
# Scan completo con detección de WAF y Sigilo
python main.py -t target.com --full --waf-detection
```

---

## 📋 Estructura del Proyecto
- `main.py`: Orquestador con inyección dinámica de PATH.
- `modules/database.py`: Gestión de SQLAlchemy y modelos.
- `modules/db_queries.py`: Inteligencia y consultas sobre la DB.
- `modules/rate_limiter.py`: El corazón del sigilo (Jitter + Kill-switch).
- `custom_templates/`: Tu arsenal secreto de firmas Nuclei.
- `output/`: Resultados estructurados por sesión.

---

## 🛡️ Uso Ético
Este framework fue creado para Bug Hunting legal y auditorías autorizadas. **No nos hacemos responsables por el mal uso de esta herramienta.**

---
**Desarrollado por el equipo de Elite con ❤️ para la comunidad de Bug Hunters.**
