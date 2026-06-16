# Security Audit Report: unitru.edu.pe

**Date:** 2026-06-15
**Tool:** OzyRecon v9.0.1 + OzyBounty
**Target:** unitru.edu.pe (Universidad Nacional de Trujillo)

---

## Executive Summary

Se identificaron **390 activos**, **257 endpoints HTTP** y **12 sitios WordPress** con exposicion de usuarios via REST API. Se encontraron **2 aplicaciones Laravel** con paneles de depuracion Ignition accessibles y **1 instancia GLPI** expuesta a internet. No se logro ejecucion remota de codigo (RCE) debido a restricciones de IP en Ignition, pero la superficie de ataque es amplia y varios sistemas contienen vulnerabilidades de informacion.

---

## 1. Inventory

| Categoria | Cantidad |
|-----------|----------|
| Subdominios totales | 390 |
| Subdominios vivos (HTTP 2xx/3xx) | 257 |
| Puertos abiertos | 0 (detras de CDN/proxy) |
| Senales generadas | 257 |
| Hipotesis generadas | 257 |

### 1.1 Tech Stack

| Tecnologia | Versiones detectadas | Hosts |
|------------|---------------------|-------|
| Apache HTTP Server | 2.4.52, 2.4.41, 2.4.54, 2.4.23, 2.2.15 | 213 |
| PHP | 8.2.0, 7.3.12, 5.5.38, 5.4.36, 5.3.3 | 32 |
| Nginx | 1.14.2, 1.27.4, 1.18.0, 1.24.0 | 13 |
| MySQL | - | 24 |
| WordPress | 6.9.4, 6.9.1, 6.9 | 15+ |
| Moodle | - | 3 |
| Joomla | 1.5 | 3 |
| Laravel | - | 2 |
| GLPI | - | 1 |
| IIS | 10.0 | 2 |
| Open Journal Systems | 3.2.1.1 | 2 |

---

## 2. Critical Findings

### CRITICAL: WordPress User Enumeration (12 sites)

**Severity:** High
**Status:** Confirmed

**Description:**
12 sitios WordPress exponen la lista completa de usuarios via `/wp-json/wp/v2/users` sin autenticacion. Esto permite a un atacante obtener nombres de usuario validos para ataques de fuerza bruta.

**Sites affected:**

| Site | Users Exposed |
|------|---------------|
| ugre.unitru.edu.pe | adminoti, ugre |
| vin.unitru.edu.pe | admvin, adminoti |
| facenf.unitru.edu.pe | adminfacenf, adminoti |
| facest.unitru.edu.pe | adminfacest, adminoti |
| hfm.unitru.edu.pe | adminoti, adminhfm |
| facmed.unitru.edu.pe | adminfacmed |
| facedu.unitru.edu.pe | jm1411 |
| facbio.unitru.edu.pe | adminfacbio |
| orni.unitru.edu.pe | admorni |
| facqui.unitru.edu.pe | alexis |
| metalurgica.unitru.edu.pe | admin |

**User `adminoti` aparece en 5 sitios diferentes**, lo que sugiere reutilizacion de credenciales entre instalaciones.

**Remediation:**
- Deshabilitar `wp-json/wp/v2/users` via funcion `rest_endpoints` en functions.php
- Instalar plugin como `Disable REST API` o `WP User Block`
- Cambiar la contrasena de `adminoti` a una unica por sitio

---

### CRITICAL: Ignition Debug Panel Expuesto (api-uraa.unitru.edu.pe)

**Severity:** High
**Status:** Confirmado (protegido parcialmente)

**Description:**
La aplicacion Laravel en `api-uraa.unitru.edu.pe` tiene el panel de depuracion Ignition accesible. El endpoint `/_ignition/health-check` confirma que `can_execute_commands: true`. El endpoint `/_ignition/execute-solution` acepta requests (HTTP 200) pero esta restringido a IP local.

**Endpoints:**

| Endpoint | Status | Notes |
|----------|--------|-------|
| `/_ignition/health-check` | 200 OK | `{"can_execute_commands": true}` |
| `/_ignition/execute-solution` | 403 Forbidden | IP restriction active |
| `/_ignition/execute-solution` (OPTIONS) | 200 OK | Endpoint exists |

**Risk:** Si un atacante obtiene acceso interno (SSRF, VPN, XSS), puede ejecutar comandos arbitrarios via Ignition RCE (CVE-2021-3129).

**Remediation:**
- Deshabilitar Ignition en produccion (`APP_DEBUG=false`)
- Configurar firewall para bloquear `/_ignition/*` a nivel de Apache/Nginx

---

### HIGH: API Laravel Endpoints Expuestos (api-uraa.unitru.edu.pe)

**Severity:** Medium-High
**Status:** Confirmado

**Description:**
La API en `api-uraa.unitru.edu.pe` expone endpoints funcionales que revelan la estructura interna del sistema.

**Endpoints:**

| Endpoint | HTTP Status | Existe? |
|----------|-------------|---------|
| `/api/tramites` | 401 | Si |
| `/api/tramites/types` | 401 | Si |
| `/api/tramites/categories` | 401 | Si |
| `/api/tramites/search` | 401 | Si |
| `/api/tramites/export` | 401 | Si |
| `/api/user` | 401 | Si |
| `/api/usuarios/login` | 404 | No |
| `/sanctum/csrf-cookie` | 404 | No |

**Stack:** Apache 2.4.52 (Ubuntu)

**Remediation:**
- Implementar rate limiting en endpoints expuestos
- No revelar nombres de rutas internas en respuestas 401
- Considerar migrar a API gateway con WAF

---

### HIGH: GLPI Expuesto a Internet (cepejup.unitru.edu.pe)

**Severity:** Medium-High
**Status:** Confirmado

**Description:**
Sistema de gestion de servicios IT (GLPI) expuesto a internet sin proteccion de red. Login page accesible y REST API funcional (`/apirest.php` responde 400 en vez de 404). GLPI tiene historial de vulnerabilidades criticas (SQLi, RCE, File Upload).

**Remediation:**
- Restringir acceso via firewall a IPs internas o VPN
- Implementar autenticacion de dos factores
- Mantener GLPI actualizado a ultima version

---

### MEDIUM: Moodle Platforms Accessible

**Severity:** Medium
**Status:** Confirmado

Plataformas Moodle detectadas:
- `aulavirtual2.unitru.edu.pe` (UNTVIRTUAL) — accesible
- `ava.unitru.edu.pe` — error SSL
- `epgvirtual.unitru.edu.pe` — error SSL

Moodle tiene CVE conocidas para enumeracion de cursos, usuarios, y en versiones antiguas, RCE.

---

### MEDIUM: Server Errors Exposing Internal State

**Severity:** Medium
**Status:** Confirmado

| Host | Error | Potencial |
|------|-------|-----------|
| esto.unitru.edu.pe | HTTP 500 | Stack trace leak |
| inf.unitru.edu.pe | HTTP 502 (Proxy Error) | Backend server info |
| dsc.unitru.edu.pe | HTTP 403 | Configuracion de acceso |
| calidad.unitru.edu.pe | HTTP 403 | Configuracion de acceso |
| din.unitru.edu.pe | HTTP 403 | Configuracion de acceso |

---

## 3. Attack Vector Analysis

### 3.1 Authentication Surface

Sistema DHUNT de autenticacion presente en ~180 endpoints. Esto representa un vector de ataque significativo si:

1. Las credenciales por defecto no fueron cambiadas
2. Existe un sistema de recuperacion de contrasenas vulnerable
3. HayRate limiting insuficiente para ataques de fuerza bruta

### 3.2 WordPress Attack Chain

```
User Enumeration (REST API) → Username list (12+ users)
    → XMLRPC brute force (multicall bypass)
    → Admin panel access
    → WordPress plugin/theme RCE
    → Server compromise
```

### 3.3 Ignition RCE Chain (requires local access)

```
Network access → SSRF/Internal access
    → _ignition/execute-solution (CVE-2021-3129)
    → RCE via log injection
    → Environment variable dump (DB creds, APP_KEY)
    → Full database access
```

---

## 4. Recommendations

### Immediate (High Priority)

1. **Disable WP user enumeration** en los 12 sitios WordPress
2. **Change `adminoti` password** en los 5 sitios donde aparece
3. **Block Ignition panel** via `.htaccess` o configuracion de Apache
4. **Restrict GLPI access** a rango de IPs internas

### Short-term (Medium Priority)

5. **Move Moodle instances** detras de autenticacion SSO
6. **Fix HTTP 500/502 errors** en esto.unitru.edu.pe e inf.unitru.edu.pe
7. **Implement rate limiting** en todos los endpoints de API
8. **Review DHUNT system** for default credentials and session security

### Long-term (Low Priority)

9. **Standardize WordPress installations** with a security baseline
10. **Implement WAF** delante de todos los servicios web
11. **Regular vulnerability scanning** with OzyRecon

---

## 5. Methodology

1. **Reconnaissance:** Subfinder + Assetfinder + DNS brute-force (390 subdomains)
2. **Discovery:** HTTPX probe (257 live hosts)
3. **Fingerprinting:** Technology detection via HTTP headers and HTML analysis
4. **Vulnerability assessment:** Manual probe of high-value targets
5. **Analysis:** Correlation and hypothesis generation via OzyBounty
6. **Validation:** Active testing of discovered vectors

---

## 6. Appendix: Detailed Endpoint Map

### WordPress Sites (confirmed)

| Subdomain | Title | CMS |
|-----------|-------|-----|
| ugre.unitru.edu.pe | Unidad de Gestion de Recursos Educativos | WordPress |
| facmed.unitru.edu.pe | FACULTAD DE MEDICINA | WordPress |
| facedu.unitru.edu.pe | FACEDU | WordPress |
| vin.unitru.edu.pe | Vicerrectorado Investigacion | WordPress |
| facenf.unitru.edu.pe | Facultad de Enfermeria | WordPress |
| facest.unitru.edu.pe | Facultad de Estomatologia | WordPress |
| facqui.unitru.edu.pe | Facultad de Ingenieria Quimica | WordPress |
| metalurgica.unitru.edu.pe | Escuela de Ing. Metalurgica | WordPress |
| hfm.unitru.edu.pe | Historia y Filosofia de la Matematica | WordPress |
| facbio.unitru.edu.pe | FACULTAD DE BIOLOGICAS | WordPress |
| industrial.unitru.edu.pe | Ingenieria Industrial | WordPress |
| orni.unitru.edu.pe | OFICINA DE RELACIONES NACIONALES E INTERNACIONALES | WordPress |
| useder.unitru.edu.pe | USE DERECHO | WordPress |
| facmed.unitru.edu.pe | FACULTAD DE MEDICINA | WordPress |
| oasis.unitru.edu.pe | Principal - OASIS | WordPress |

### Laravel Applications

| Subdomain | Title | Notes |
|-----------|-------|-------|
| api-uraa.unitru.edu.pe | (API) | Apache/2.4.52 Ubuntu, Ignition panel |
| asistencia.unitru.edu.pe | Sistema Registro Actividades | Login page, API endpoints |

### Notable Applications

| Subdomain | Title | Platform |
|-----------|-------|----------|
| cepejup.unitru.edu.pe | Authentication - GLPI | GLPI IT Management |
| apps-bkn.unitru.edu.pe | A FeathersJS application | Node.js/FeathersJS |
| aulavirtual2.unitru.edu.pe | UNTVIRTUAL | Moodle |
| museozoo.unitru.edu.pe | Bienvenidos a la portada | Joomla |
| intranet.unitru.edu.pe | Intranet UNT | Nginx |
| repositorio.unitru.edu.pe | (redirect) | DSpace probable |
| transparencia.unitru.edu.pe | Portal de Transparencia | - |
| diplomas.unitru.edu.pe | GRADOS Y TITULOS - UNT | - |
| suv.unitru.edu.pe | SUV Ingreso | Nginx |
| suv2.unitru.edu.pe | SUV Ingreso | Nginx + API |

---

*Report generated by OzyRecon v9.0.1 + OzyBounty*
