---
**Classification:** CONFIDENTIAL — For Authorized Recipients Only
---

# Security Assessment Report

| Field | Value |
|-------|-------|
| **Target** | `unitru.edu.pe` |
| **Date** | 2026-06-15 |
| **Engine** | OzyRecon v9.0.1 + OzyBounty |
| **Scope** | unitru.edu.pe |
| **Assets Discovered** | 390 |
| **Endpoints Mapped** | 257 |
| **Hypotheses Generated** | 257 |

## Executive Summary

This report presents the findings of a security assessment conducted against 
`unitru.edu.pe`. A total of **390 assets** were identified, with 
**257 live endpoints** mapped. The assessment generated 
**257 security hypotheses**, of which the highest-scoring 
items are detailed below.

### Key Metrics

| Metric | Count |
|--------|-------|
| Subdomains Discovered | 390 |
| Live HTTP Endpoints | 257 |
| Security Signals | 257 |
| Testable Hypotheses | 257 |
| Unique Technologies | 110 |

### Technology Stack

| Technology | Instances |
|------------|----------|
| Apache HTTP Server | 213 |
| PHP | 32 |
| MySQL | 24 |
| Bootstrap | 20 |
| Ubuntu | 10 |
| Apache HTTP Server:2.4.52 | 9 |
| Google Hosted Libraries | 8 |
| Font Awesome | 7 |
| HTTP/3 | 6 |
| Joomla:1.5 | 6 |
| MooTools | 6 |
| Nginx:1.14.2 | 6 |
| HSTS | 5 |
| WordPress Block Editor | 5 |
| Bootstrap:3.3.7 | 5 |

## Findings Summary

| Severity | Count |
|----------|-------|
| **MEDIUM** | 257 |
| **LOW** | 257 |

## Detailed Findings

---

### Finding #1: WordPress User Enumeration via REST API

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N/E:F` |
| **CVSS Score** | 4.6/10 |
| **Category** | Information Disclosure |

#### Description

**5** WordPress installations were found to expose user accounts via the REST API at `/wp-json/wp/v2/users`. This allows unauthenticated attackers to enumerate valid usernames for brute-force or phishing attacks. The user `adminoti` was identified across multiple independent installations, suggesting credential reuse.

#### Affected Assets

- `arquitectura.unitru.edu.pe`
- `matesc.unitru.edu.pe`
- `fastworkshopmathematics.unitru.edu.pe`
- `sisdef.unitru.edu.pe`
- `hfm.unitru.edu.pe`
- *... and 2 more*

#### Evidence

- **GET** `https://{site}/wp-json/wp/v2/users` → `200`

#### Remediation

1. Disable the REST API users endpoint: add `remove_action('rest_api_init', 'wp_rest_user_controller');` to functions.php
2. Install a security plugin (e.g., Wordfence, Sucuri) to block user enumeration
3. Implement unique credentials per WordPress installation

#### References

- [OWASP - User Enumeration](https://owasp.org/www-community/attacks/Username_Enumeration)

---

### Finding #2: Laravel Ignition Debug Panel Exposed

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P` |
| **CVSS Score** | 5.2/10 |
| **Category** | Security Misconfiguration |

#### Description

The Laravel Ignition debug panel was found accessible on at least one subdomain. The health-check endpoint (`/_ignition/health-check`) confirms `can_execute_commands: true`. While the `execute-solution` endpoint is restricted to local IP, this represents a significant security risk if an attacker gains internal network access.

#### Affected Assets

- `api-uraa.unitru.edu.pe`
- `asistencia.unitru.edu.pe`

#### Evidence

- **GET** `https://api-uraa.unitru.edu.pe/_ignition/health-check?format=json` → `200`
  - Response: `{"can_execute_commands":true}`
- **POST** `https://api-uraa.unitru.edu.pe/_ignition/execute-solution` → `403`
  - Response: `IP restricted`

#### Remediation

1. Set `APP_DEBUG=false` and `APP_ENV=production` in `.env`
2. Block `/_ignition/*` routes in web server config:
   ```apache
   <LocationMatch /_ignition>
       Require ip 127.0.0.1
   </LocationMatch>
   ```
3. Upgrade Ignition to the latest version (>= 2.5.2)

#### References

- [CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129)
- [Laravel Ignition Docs](https://flareapp.io/docs/ignition-for-laravel/introduction)

---

### Finding #3: Outdated Software Versions Detected

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P` |
| **CVSS Score** | 4.8/10 |
| **Category** | Patch Management |

#### Description

The following outdated software versions were detected: PHP 5.4.36 (2014), Apache 2.2.15 (2011), PHP 5.5.38 (2016), PHP 5.3.3 (2012). These versions are no longer supported and contain known vulnerabilities.

#### Affected Assets

- `www.sga2018.unitru.edu.pe`
- `www.aplicaciones.unitru.edu.pe`
- `sga2018.unitru.edu.pe`
- `aplicaciones.unitru.edu.pe`
- `picfedu.unitru.edu.pe`
- *... and 1 more*

#### Evidence


#### Remediation

Update all software to vendor-supported versions. Establish a regular patch management cycle.

#### References

- [CVE Database](https://cve.mitre.org)

---

### Finding #4: Exposed Administrative and API Endpoints

| Field | Value |
|-------|-------|
| **Severity** | **MEDIUM** |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:P` |
| **CVSS Score** | 4.1/10 |
| **Category** | Exposed Surface |

#### Description

Multiple administrative panels and API endpoints were found accessible without authentication. Notable examples include the GLPI IT management system, API endpoint structure disclosure, and various intranet portals.

#### Affected Assets

- `cepejup.unitru.edu.pe (GLPI)`
- `api-uraa.unitru.edu.pe (API)`
- `intranet.unitru.edu.pe (Intranet)`
- `diplomas.unitru.edu.pe (Grados y Titulos)`

#### Evidence


#### Remediation

1. Restrict administrative interfaces to VPN/internal networks
2. Implement authentication gateway for all API endpoints
3. Deploy WAF to protect exposed services

#### References

- [OWASP - Attack Surface Analysis](https://owasp.org/www-project-attack-surface-analysis/)

## Recommendations

| Priority | Action |
|----------|--------|
| Immediate | Disable WP REST API user enumeration on all identified WordPress sites |
| Immediate | Restrict Ignition debug panel access to internal IPs only |
| Immediate | Change shared administrative credentials across all CMS platforms |
| Short-term | Implement rate limiting on all exposed API endpoints |
| Short-term | Move GLPI and management consoles behind VPN |
| Medium-term | Establish a patch management process for CMS platforms |
| Medium-term | Implement WAF with OWASP CRS ruleset |

## Methodology

This assessment was conducted using a multi-phase reconnaissance and analysis pipeline:

| Phase | Activity | Tools |
|-------|----------|-------|
| 1. Passive Recon | Subdomain enumeration via public sources | Subfinder, Assetfinder |
| 2. Active Recon | DNS resolution, HTTP probing | DNSx, HTTPx |
| 3. Fingerprinting | Technology detection, version identification | HTTPx, Wappalyzer |
| 4. Service Analysis | Port scanning, service version detection | Naabu, Nmap |
| 5. Intelligence | Pattern analysis, hypothesis generation | OzyRecon Engine |
| 6. Expert Validation | Manual verification of high-value findings | Analyst |

## Appendix: Complete Asset Inventory

| Host | Status | Title | Technologies |
|------|--------|-------|--------------|
| ablogs.unitru.edu.pe | - |  |  |
| accf.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,M |
| accf2.unitru.edu.pe | - |  | Apache HTTP Server |
| acde.unitru.edu.pe | - |  | Apache HTTP Server |
| acmgmat.unitru.edu.pe | - |  | Apache HTTP Server |
| acreditacionmedicina.unitru.edu.pe | - |  | Apache HTTP Server |
| adm.unitru.edu.pe | - |  |  |
| admision.unitru.edu.pe | - |  |  |
| admisionapps.unitru.edu.pe | - |  |  |
| agri.unitru.edu.pe | - |  |  |
| agric.unitru.edu.pe | - |  | Apache HTTP Server |
| agro.unitru.edu.pe | - |  | Apache HTTP Server |
| agroin.unitru.edu.pe | - |  |  |
| agroind.unitru.edu.pe | - |  | Apache HTTP Server |
| agrono.unitru.edu.pe | - |  |  |
| ant.unitru.edu.pe | - |  | Apache HTTP Server |
| apemerit.unitru.edu.pe | - |  | Apache HTTP Server |
| api-uraa.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Ubun |
| aplicaciones.unitru.edu.pe | - |  | Apache HTTP Server,Debian:sque |
| apps-bkn.unitru.edu.pe | - |  | HSTS,Nginx:1.14.2 |
| aries.unitru.edu.pe | - |  |  |
| arq.unitru.edu.pe | - |  | Apache HTTP Server |
| arquitectura.unitru.edu.pe | - |  | Apache HTTP Server,MySQL,PHP,W |
| asistencia.unitru.edu.pe | - |  | Apache HTTP Server,Laravel,PHP |
| aula.cestunt.unitru.edu.pe | - |  |  |
| aula.unitru.edu.pe | - |  |  |
| aulademos.unitru.edu.pe | - |  |  |
| aulafacedu.unitru.edu.pe | - |  |  |
| aulavirtual.unitru.edu.pe | - |  | Apache HTTP Server |
| aulavirtual2.unitru.edu.pe | - |  | Apache HTTP Server:2.4.41,Boot |
| aulavirtualpg.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap:3 |
| auspicios.unitru.edu.pe | - |  | Google Maps,LottieFiles,Nginx: |
| ava.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,M |
| beca18.unitru.edu.pe | - |  | Apache HTTP Server |
| biblioteca-intra.unitru.edu.pe | - |  | Bootstrap:25.0506000,HSTS,HTTP |
| biblioteca.unitru.edu.pe | - |  | Bootstrap:25.0506000,HSTS,HTTP |
| bibliotecas.unitru.edu.pe | - |  |  |
| bicentenariount.unitru.edu.pe | - |  |  |
| bienestarfarm.unitru.edu.pe | - |  |  |
| bio.unitru.edu.pe | - |  | Apache HTTP Server |
| boletasdepago.unitru.edu.pe | - |  | Apache HTTP Server |
| bolsa.unitru.edu.pe | - |  | Apache HTTP Server |
| buscaresoluciones.unitru.edu.pe | - |  |  |
| calidad.unitru.edu.pe | - |  | Apache HTTP Server |
| capacitaciones.unitru.edu.pe | - |  |  |
| capu.unitru.edu.pe | - |  | Apache HTTP Server |
| ccal.unitru.edu.pe | - |  |  |
| cci.unitru.edu.pe | - |  | Apache HTTP Server |
| ccifbiperu2021.unitru.edu.pe | - |  | Apache HTTP Server |
| ccom.unitru.edu.pe | - |  | Apache HTTP Server |
| cepejup.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Ubun |
| cepunt.unitru.edu.pe | - |  |  |
| cestunt.unitru.edu.pe | - |  | Apache HTTP Server |
| ceua.unitru.edu.pe | - |  |  |
| chanchan.unitru.edu.pe | - |  |  |
| chimor.unitru.edu.pe | - |  |  |
| cicec.unitru.edu.pe | - |  |  |
| cidunt.unitru.edu.pe | - |  |  |
| ciduntregmat.unitru.edu.pe | - |  | Apache HTTP Server |
| ciei.unitru.edu.pe | - |  | Apache HTTP Server |
| compite.unitru.edu.pe | - |  | Apache HTTP Server |
| coneimin.unitru.edu.pe | - |  |  |
| conimat.unitru.edu.pe | - |  | Apache HTTP Server |
| cont.unitru.edu.pe | - |  | Apache HTTP Server |
| contact.unitru.edu.pe | - |  |  |
| control.unitru.edu.pe | - |  |  |
| copefi.unitru.edu.pe | - |  | Apache HTTP Server |
| correo.unitru.edu.pe | - |  |  |
| coteca.unitru.edu.pe | - |  | Apache HTTP Server |
| covid19.unitru.edu.pe | - |  | Apache HTTP Server |
| cris.unitru.edu.pe | - |  | HTTP/3 |
| cuiciti.unitru.edu.pe | - |  | Apache HTTP Server |
| dblogs.unitru.edu.pe | - |  |  |
| dcep.unitru.edu.pe | - |  |  |
| dda.unitru.edu.pe | - |  | Apache HTTP Server |
| demos.unitru.edu.pe | - |  |  |
| depestad.unitru.edu.pe | - |  | Apache HTTP Server |
| depfis.unitru.edu.pe | - |  |  |
| depidiomas.unitru.edu.pe | - |  | Apache HTTP Server |
| deplengualit.unitru.edu.pe | - |  | Apache HTTP Server |
| depmath.unitru.edu.pe | - |  | Apache HTTP Server |
| depmecanica.unitru.edu.pe | - |  | Apache HTTP Server |
| depmorfologia.unitru.edu.pe | - |  | Apache HTTP Server |
| der.unitru.edu.pe | - |  |  |
| dga.unitru.edu.pe | - |  | Apache HTTP Server |
| dic.unitru.edu.pe | - |  | Apache HTTP Server,Joomla:1.5, |
| digitalunt.unitru.edu.pe | - |  | Apache HTTP Server |
| din.unitru.edu.pe | - |  | Apache HTTP Server |
| dipseu.unitru.edu.pe | - |  |  |
| dirplan.unitru.edu.pe | - |  | Apache HTTP Server |
| disee.unitru.edu.pe | - |  | Apache HTTP Server |
| ditt.unitru.edu.pe | - |  | Apache HTTP Server |
| docs.unitru.edu.pe | - |  |  |
| drni.unitru.edu.pe | - |  |  |
| drsu.unitru.edu.pe | - |  | Apache HTTP Server |
| drt.unitru.edu.pe | - |  |  |
| dsapce.unitru.edu.pe | - |  |  |
| dsc.unitru.edu.pe | - |  | Apache HTTP Server |
| dsic.unitru.edu.pe | - |  |  |
| dspace.unitru.edu.pe | - |  |  |
| eco.unitru.edu.pe | - |  |  |
| econ.unitru.edu.pe | - |  | Apache HTTP Server |
| editorial.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:3 |
| educaunt.unitru.edu.pe | - |  |  |
| eduini.unitru.edu.pe | - |  | Apache HTTP Server |
| edupri.unitru.edu.pe | - |  |  |
| edusec.unitru.edu.pe | - |  |  |
| edusecll.unitru.edu.pe | - |  | Apache HTTP Server |
| egunt.unitru.edu.pe | - |  | Apache HTTP Server |
| elbolivarianonoticias.unitru.edu.pe | - |  | Apache HTTP Server |
| encuestas.unitru.edu.pe | - |  | AlertifyJS,Apache HTTP Server, |
| enf.unitru.edu.pe | - |  |  |
| epgnew.unitru.edu.pe | - |  | Apache HTTP Server:2.4.41,Boot |
| epgvirtual.unitru.edu.pe | - |  | Apache HTTP Server:2.4.41,Mood |
| est.unitru.edu.pe | - |  | Apache HTTP Server |
| esto.unitru.edu.pe | - |  | Apache HTTP Server |
| eticaingenieria.unitru.edu.pe | - |  | Nginx:1.18.0,Ubuntu |
| facagro.unitru.edu.pe | - |  | Apache HTTP Server |
| facbio.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,C |
| faccfm.unitru.edu.pe | - |  | Apache HTTP Server |
| facder.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,L |
| faceco.unitru.edu.pe | - |  | Apache HTTP Server |
| facedu.unitru.edu.pe | - |  | Apache HTTP Server,Backbone.js |
| facenf.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:3 |
| facenf2.unitru.edu.pe | - |  |  |
| facest.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:3 |
| facesto.unitru.edu.pe | - |  |  |
| facfar.unitru.edu.pe | - |  | Apache HTTP Server:2.4.54,Node |
| facing.unitru.edu.pe | - |  | Apache HTTP Server |
| facmed.unitru.edu.pe | - |  | Apache HTTP Server,MySQL,PHP,W |
| facqui.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:3 |
| facsoc.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:3 |
| far.unitru.edu.pe | - |  |  |
| fastworkshopmathematics.unitru.edu.pe | - |  | Apache HTTP Server,Cryout Crea |
| ffccee.unitru.edu.pe | - |  | Apache HTTP Server,Joomla:1.5, |
| fis.unitru.edu.pe | - |  | Apache HTTP Server |
| fvirtual.unitru.edu.pe | - |  | Apache HTTP Server |
| gcp.unitru.edu.pe | - |  | Apache HTTP Server |
| gestionti-sistemasxxv.unitru.edu.pe | - |  | HSTS,Vercel |
| gitlab.ccal.unitru.edu.pe | - |  |  |
| gpcd.unitru.edu.pe | - |  | Apache HTTP Server |
| gpd.unitru.edu.pe | - |  |  |
| gri.unitru.edu.pe | - |  | Apache HTTP Server |
| hfm.unitru.edu.pe | - |  | Apache HTTP Server,MySQL,PHP,W |
| hist.unitru.edu.pe | - |  | Apache HTTP Server |
| ind.unitru.edu.pe | - |  | Apache HTTP Server |
| industrial.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:3 |
| inf.unitru.edu.pe | - |  | Apache HTTP Server |
| inf2.unitru.edu.pe | - |  | Apache HTTP Server |
| infounitru.unitru.edu.pe | - |  | Apache HTTP Server |
| infvalle.unitru.edu.pe | - |  | Apache HTTP Server |
| iniciativas.unitru.edu.pe | - |  | Apache HTTP Server |
| insin.unitru.edu.pe | - |  | Apache HTTP Server |
| intranet.unitru.edu.pe | - |  | LottieFiles,Nginx:1.14.2,Unpkg |
| isaca.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,F |
| jornadas.unitru.edu.pe | - |  |  |
| lenguayliteratura.unitru.edu.pe | - |  | Apache HTTP Server,YouTube |
| mail.adm.unitru.edu.pe | - |  |  |
| mail.agri.unitru.edu.pe | - |  |  |
| mail.agroin.unitru.edu.pe | - |  |  |
| mail.agrono.unitru.edu.pe | - |  |  |
| mail.ant.unitru.edu.pe | - |  |  |
| mail.ccom.unitru.edu.pe | - |  |  |
| mail.cont.unitru.edu.pe | - |  |  |
| mail.der.unitru.edu.pe | - |  |  |
| mail.vtindustrial.unitru.edu.pe | - |  |  |
| mat.unitru.edu.pe | - |  |  |
| materiales.unitru.edu.pe | - |  | Apache HTTP Server |
| matesc.unitru.edu.pe | - |  | Apache HTTP Server,MySQL,PHP,S |
| math.unitru.edu.pe | - |  | Apache HTTP Server |
| mathdep.unitru.edu.pe | - |  | Apache HTTP Server |
| mathesc.unitru.edu.pe | - |  | Apache HTTP Server |
| mec.unitru.edu.pe | - |  |  |
| mecatronica.unitru.edu.pe | - |  |  |
| med.unitru.edu.pe | - |  |  |
| met.unitru.edu.pe | - |  |  |
| metalurgica.unitru.edu.pe | - |  | Apache HTTP Server,ContentView |
| min.unitru.edu.pe | - |  | Apache HTTP Server |
| minas.unitru.edu.pe | - |  |  |
| msn.unitru.edu.pe | - |  |  |
| mural.unitru.edu.pe | - |  | Apache HTTP Server |
| museozoo.unitru.edu.pe | - |  | Apache HTTP Server,Joomla:1.5, |
| mypa.unitru.edu.pe | - |  |  |
| ns.unitru.edu.pe | - |  |  |
| oasis.unitru.edu.pe | - |  | Apache HTTP Server,Contact For |
| oca.unitru.edu.pe | - |  |  |
| ogbu.unitru.edu.pe | - |  | Apache HTTP Server |
| ogdae.unitru.edu.pe | - |  |  |
| oia.unitru.edu.pe | - |  |  |
| opdi.unitru.edu.pe | - |  |  |
| orni.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,M |
| ort.unitru.edu.pe | - |  | Apache HTTP Server |
| osb.unitru.edu.pe | - |  | Apache HTTP Server |
| osi.unitru.edu.pe | - |  |  |
| otcc.unitru.edu.pe | - |  | Apache HTTP Server |
| ote.unitru.edu.pe | - |  |  |
| padresapp.unitru.edu.pe | - |  |  |
| padressuv.unitru.edu.pe | - |  | Apache HTTP Server |
| pagina2.unitru.edu.pe | - |  | Apache HTTP Server |
| pap.unitru.edu.pe | - |  | Apache HTTP Server |
| pedi2050.unitru.edu.pe | - |  | Apache HTTP Server |
| pei.unitru.edu.pe | - |  | Apache HTTP Server |
| pes.unitru.edu.pe | - |  |  |
| pesq.unitru.edu.pe | - |  | Apache HTTP Server |
| pg.unitru.edu.pe | - |  |  |
| pic9.unitru.edu.pe | - |  | Apache HTTP Server |
| picfedu.unitru.edu.pe | - |  | Apache HTTP Server:2.2.15,Boot |
| planbic.unitru.edu.pe | - |  | Apache HTTP Server |
| portalpadres.unitru.edu.pe | - |  | Apache HTTP Server |
| posgrado.unitru.edu.pe | - |  | Apache HTTP Server:2.4.41,Boot |
| postapps.unitru.edu.pe | - |  | Apache HTTP Server |
| preford.unitru.edu.pe | - |  | Apache HTTP Server |
| prosein.unitru.edu.pe | - |  | Apache HTTP Server |
| proyectoremove.unitru.edu.pe | - |  |  |
| pruebas.unitru.edu.pe | - |  |  |
| qa-solvencias.unitru.edu.pe | - |  |  |
| qui.unitru.edu.pe | - |  | Apache HTTP Server |
| reclamaciones.unitru.edu.pe | - |  | Apache HTTP Server |
| repositorio.unitru.edu.pe | - |  | HSTS,HTTP/3 |
| reservaonline.unitru.edu.pe | - |  | Apache HTTP Server |
| resoluciones.unitru.edu.pe | - |  | Google Maps,LottieFiles,Nginx: |
| revistas.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Boot |
| rsu.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap:5 |
| secgen.unitru.edu.pe | - |  | Apache HTTP Server |
| sede-huamachuco.unitru.edu.pe | - |  | Apache HTTP Server |
| sede-jequetepeque.unitru.edu.pe | - |  | Apache HTTP Server |
| sede-otuzco.unitru.edu.pe | - |  |  |
| sede-stgochuco.unitru.edu.pe | - |  |  |
| sete.unitru.edu.pe | - |  | Apache HTTP Server |
| seunt.use-dpa.unitru.edu.pe | - |  | Apache HTTP Server |
| sga2018.unitru.edu.pe | - |  | Apache HTTP Server:2.4.23,ExtJ |
| sgdunt.unitru.edu.pe | - |  | Apache HTTP Server |
| siga.unitru.edu.pe | - |  | Apache HTTP Server |
| siplan.unitru.edu.pe | - |  | Apache HTTP Server |
| sis.unitru.edu.pe | - |  |  |
| sisav.unitru.edu.pe | - |  |  |
| sisdef.unitru.edu.pe | - |  | Apache HTTP Server,Elementor:4 |
| sisgedo.unitru.edu.pe | - |  |  |
| sistemas.unitru.edu.pe | - |  | Google Maps,LottieFiles,Nginx: |
| soc.unitru.edu.pe | - |  |  |
| solvencia.unitru.edu.pe | - |  | Apache HTTP Server |
| suv.unitru.edu.pe | - |  | Bootstrap:3.3.7,BootstrapCDN:3 |
| suv2.unitru.edu.pe | - |  | Bootstrap:3.3.7,BootstrapCDN:3 |
| trabajosoc.unitru.edu.pe | - |  | Apache HTTP Server |
| tramites-uraa.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Swee |
| transparencia-academica.unitru.edu.pe | - |  |  |
| transparencia-universitaria.unitru.edu.pe | - |  | Next.js,Nginx:1.18.0,Node.js,R |
| transparencia.unitru.edu.pe | - |  | Apache HTTP Server |
| tsoc.unitru.edu.pe | - |  |  |
| tur.unitru.edu.pe | - |  | Apache HTTP Server |
| turismo.unitru.edu.pe | - |  | Apache HTTP Server,Cryout Crea |
| ucap.unitru.edu.pe | - |  | Apache HTTP Server |
| udifec.unitru.edu.pe | - |  | Apache HTTP Server |
| uesc.unitru.edu.pe | - |  | Apache HTTP Server |
| ugre.unitru.edu.pe | - |  | Apache HTTP Server,Contact For |
| uniestadistica.unitru.edu.pe | - |  | Apache HTTP Server,Cryout Crea |
| unitru.edu.pe | - |  | Bootstrap,IIS:10.0,Microsoft A |
| unt2014.unitru.edu.pe | - |  | Apache HTTP Server |
| untempresa.unitru.edu.pe | - |  | Apache HTTP Server |
| uraa.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Ubun |
| use-dpa.unitru.edu.pe | - |  | Bootstrap,Font Awesome,HTTP/3, |
| use-facfar.unitru.edu.pe | - |  | Apache HTTP Server:2.4.54,Open |
| use.unitru.edu.pe | - |  | Moodle,Nginx:1.24.0,PHP,Ubuntu |
| useder.unitru.edu.pe | - |  | Apache HTTP Server,Backbone.js |
| usee.unitru.edu.pe | - |  |  |
| vac.unitru.edu.pe | - |  | Apache HTTP Server |
| vin.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Cont |
| visitas.unitru.edu.pe | - |  | Google Maps,LottieFiles,Nginx: |
| vtindustrial.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,F |
| web2.unitru.edu.pe | - |  | Apache HTTP Server |
| www.accf.unitru.edu.pe | - |  | Apache HTTP Server |
| www.acde.unitru.edu.pe | - |  | Apache HTTP Server |
| www.acmgmat.unitru.edu.pe | - |  | Apache HTTP Server |
| www.acreditacionmedicina.unitru.edu.pe | - |  | Apache HTTP Server |
| www.adm.unitru.edu.pe | - |  |  |
| www.admision.unitru.edu.pe | - |  |  |
| www.admison.unitru.edu.pe | - |  |  |
| www.agri.unitru.edu.pe | - |  |  |
| www.agric.unitru.edu.pe | - |  | Apache HTTP Server |
| www.agro.unitru.edu.pe | - |  | Apache HTTP Server |
| www.agroin.unitru.edu.pe | - |  |  |
| www.agroind.unitru.edu.pe | - |  | Apache HTTP Server |
| www.agrono.unitru.edu.pe | - |  |  |
| www.amb.unitru.edu.pe | - |  |  |
| www.ant.unitru.edu.pe | - |  | Apache HTTP Server |
| www.aplicaciones.unitru.edu.pe | - |  | Apache HTTP Server,Debian:sque |
| www.arque.unitru.edu.pe | - |  |  |
| www.aula.unitru.edu.pe | - |  |  |
| www.aulavirtual.unitru.edu.pe | - |  | Apache HTTP Server |
| www.bibliotecas.unitru.edu.pe | - |  |  |
| www.bibliotecasunt.unitru.edu.pe | - |  |  |
| www.bio.unitru.edu.pe | - |  | Apache HTTP Server |
| www.bolsa.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ccal.unitru.edu.pe | - |  |  |
| www.cci.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ccom.unitru.edu.pe | - |  | Apache HTTP Server |
| www.cepejup.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Ubun |
| www.cepunt.unitru.edu.pe | - |  |  |
| www.cestunt.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ceua.unitru.edu.pe | - |  |  |
| www.chanchan.unitru.edu.pe | - |  |  |
| www.cicec.unitru.edu.pe | - |  |  |
| www.cidunt.unitru.edu.pe | - |  |  |
| www.conaets.unitru.edu.pe | - |  |  |
| www.coneimin.unitru.edu.pe | - |  |  |
| www.conimat.unitru.edu.pe | - |  | Apache HTTP Server |
| www.cont.unitru.edu.pe | - |  | Apache HTTP Server |
| www.contact.unitru.edu.pe | - |  |  |
| www.copefi.unitru.edu.pe | - |  | Apache HTTP Server |
| www.correo.unitru.edu.pe | - |  |  |
| www.der.unitru.edu.pe | - |  |  |
| www.dic.unitru.edu.pe | - |  | Apache HTTP Server,Joomla:1.5, |
| www.din.unitru.edu.pe | - |  | Apache HTTP Server |
| www.diplomas.unitru.edu.pe | - |  | Apache HTTP Server:2.4.6,Boots |
| www.dipseu.unitru.edu.pe | - |  |  |
| www.dirplan.unitru.edu.pe | - |  | Apache HTTP Server |
| www.drsu.unitru.edu.pe | - |  | Apache HTTP Server |
| www.dsic.unitru.edu.pe | - |  |  |
| www.dspace.unitru.edu.pe | - |  |  |
| www.econ.unitru.edu.pe | - |  | Apache HTTP Server |
| www.editorial.unitru.edu.pe | - |  | Apache HTTP Server |
| www.eduini.unitru.edu.pe | - |  | Apache HTTP Server |
| www.edupri.unitru.edu.pe | - |  |  |
| www.edusec.unitru.edu.pe | - |  |  |
| www.egunt.unitru.edu.pe | - |  | Apache HTTP Server |
| www.enfermeria.unitru.edu.pe | - |  |  |
| www.est.unitru.edu.pe | - |  | Apache HTTP Server |
| www.esto.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facagro.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facbio.unitru.edu.pe | - |  | Apache HTTP Server |
| www.faccfm.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facder.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,L |
| www.facedu.unitru.edu.pe | - |  | Apache HTTP Server,Backbone.js |
| www.facenf.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facenf2.unitru.edu.pe | - |  |  |
| www.facfar.unitru.edu.pe | - |  | Apache HTTP Server:2.4.54,Node |
| www.facing.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facmed.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facqui.unitru.edu.pe | - |  | Apache HTTP Server |
| www.facsoc.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ffccee.unitru.edu.pe | - |  | Apache HTTP Server,Joomla:1.5, |
| www.fis.unitru.edu.pe | - |  | Apache HTTP Server |
| www.fvirtual.unitru.edu.pe | - |  | Apache HTTP Server |
| www.helpdesk.unitru.edu.pe | - |  |  |
| www.ind.unitru.edu.pe | - |  | Apache HTTP Server |
| www.inf.unitru.edu.pe | - |  | Apache HTTP Server |
| www.inf2.unitru.edu.pe | - |  | Apache HTTP Server |
| www.infounitru.unitru.edu.pe | - |  | Apache HTTP Server |
| www.jornadas.unitru.edu.pe | - |  |  |
| www.mat.unitru.edu.pe | - |  |  |
| www.materiales.unitru.edu.pe | - |  | Apache HTTP Server |
| www.math.unitru.edu.pe | - |  | Apache HTTP Server |
| www.mathdep.unitru.edu.pe | - |  | Apache HTTP Server |
| www.mathesc.unitru.edu.pe | - |  | Apache HTTP Server |
| www.met.unitru.edu.pe | - |  |  |
| www.metalurgica.unitru.edu.pe | - |  | Apache HTTP Server |
| www.min.unitru.edu.pe | - |  |  |
| www.museozoo.unitru.edu.pe | - |  | Apache HTTP Server,Joomla:1.5, |
| www.oac.unitru.edu.pe | - |  | Apache HTTP Server |
| www.oca.unitru.edu.pe | - |  |  |
| www.ogbu.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ogdae.unitru.edu.pe | - |  |  |
| www.oia.unitru.edu.pe | - |  |  |
| www.ort.unitru.edu.pe | - |  | Apache HTTP Server |
| www.osb.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ote.unitru.edu.pe | - |  |  |
| www.pei.unitru.edu.pe | - |  | Apache HTTP Server |
| www.picfedu.unitru.edu.pe | - |  | Apache HTTP Server:2.2.15,Boot |
| www.planbic.unitru.edu.pe | - |  | Apache HTTP Server |
| www.postapps.unitru.edu.pe | - |  |  |
| www.pruebas.unitru.edu.pe | - |  |  |
| www.qa-solvencias.unitru.edu.pe | - |  |  |
| www.qui.unitru.edu.pe | - |  | Apache HTTP Server |
| www.revistas.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Boot |
| www.secgen.unitru.edu.pe | - |  | Apache HTTP Server |
| www.sga2018.unitru.edu.pe | - |  | Apache HTTP Server:2.4.23,ExtJ |
| www.sgdunt.unitru.edu.pe | - |  | Apache HTTP Server |
| www.solvencia.unitru.edu.pe | - |  | Apache HTTP Server |
| www.suv.unitru.edu.pe | - |  | Bootstrap:3.3.7,BootstrapCDN:3 |
| www.suv2.unitru.edu.pe | - |  | Bootstrap:3.3.7,BootstrapCDN:3 |
| www.trabajosoc.unitru.edu.pe | - |  |  |
| www.transparencia.unitru.edu.pe | - |  | Apache HTTP Server |
| www.ucap.unitru.edu.pe | - |  | Apache HTTP Server |
| www.unitru.edu.pe | - |  | Bootstrap,IIS:10.0,Microsoft A |
| www.use-dpa.unitru.edu.pe | - |  | Bootstrap,Font Awesome,HTTP/3, |
| www.usee.unitru.edu.pe | - |  |  |
| www.vac.unitru.edu.pe | - |  | Apache HTTP Server |
| www.vin.unitru.edu.pe | - |  | Apache HTTP Server:2.4.52,Ubun |
| www.vtindustrial.unitru.edu.pe | - |  | Apache HTTP Server,Bootstrap,F |
| zoo.unitru.edu.pe | - |  |  |

---
*Report generated automatically by OzyRecon v9.0.1 + OzyBounty*
*This document contains confidential information. Do not distribute without authorization.*
