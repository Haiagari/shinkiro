---
**Classification:** CONFIDENTIAL — For Authorized Recipients Only
---

# Security Assessment Report

| Field | Value |
|-------|-------|
| **Target** | `insforge.dev` |
| **Date** | 2026-06-15 |
| **Engine** | OzyRecon v9.0.1 + OzyBounty |
| **Scope** | *.insforge.dev, insforge.dev |
| **Assets Discovered** | 21 |
| **Endpoints Mapped** | 18 |
| **Hypotheses Generated** | 18 |

## Executive Summary

This report presents the findings of a security assessment conducted against 
`insforge.dev`. A total of **21 assets** were identified, with 
**18 live endpoints** mapped. The assessment generated 
**18 security hypotheses**, of which the highest-scoring 
items are detailed below.

### Key Metrics

| Metric | Count |
|--------|-------|
| Subdomains Discovered | 21 |
| Live HTTP Endpoints | 18 |
| Security Signals | 18 |
| Testable Hypotheses | 18 |
| Unique Technologies | 15 |

### Technology Stack

| Technology | Instances |
|------------|----------|
| HSTS | 9 |
| Node.js | 5 |
| Next.js | 4 |
| React | 4 |
| Linkedin Ads | 3 |
| Cloudflare | 3 |
| Amazon Web Services | 3 |
| Vercel | 3 |
| Amazon CloudFront | 2 |
| Amazon S3 | 2 |
| Cloudflare Browser Insights | 2 |
| Nginx:1.28.0 | 1 |
| HTTP/3 | 1 |
| Express | 1 |
| Amazon ELB | 1 |

## Findings Summary

| Severity | Count |
|----------|-------|
| **MEDIUM** | 18 |
| **LOW** | 18 |

## Detailed Findings

---

### Finding #1: Exposed Administrative and API Endpoints

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
| api-beta.insforge.dev | - |  | HSTS |
| api.insforge.dev | - |  | HSTS |
| b.insforge.dev | - |  | Cloudflare,HSTS |
| cdn.insforge.dev | - |  | Amazon CloudFront,Amazon S3,Am |
| config.insforge.dev | - |  | Amazon CloudFront,Amazon S3,Am |
| development.insforge.dev | - |  | HSTS,Linkedin Ads,Next.js,Node |
| docs.insforge.dev | - |  | Cloudflare,Cloudflare Browser  |
| feedback.insforge.dev | - |  | Cloudflare,Cloudflare Browser  |
| go.insforge.dev | - |  | HSTS,Next.js,Node.js,React,Ver |
| insforge.dev | - |  | HSTS,Linkedin Ads,Next.js,Node |
| mcp.insforge.dev | - |  | Express,Node.js |
| monitoring-beta.insforge.dev | - |  |  |
| monitoring.insforge.dev | - |  | Amazon ELB,Amazon Web Services |
| staging.insforge.dev | - |  | HSTS,Linkedin Ads,Next.js,Node |
| storage-cdn-beta.insforge.dev | - |  |  |
| storage-cdn-test.insforge.dev | - |  |  |
| sudo-beta.insforge.dev | - |  |  |
| sudo.insforge.dev | - |  |  |
| tags.insforge.dev | - |  |  |
| track.insforge.dev | - |  | Nginx:1.28.0 |
| www.insforge.dev | - |  | HSTS,Vercel |

---
*Report generated automatically by OzyRecon v9.0.1 + OzyBounty*
*This document contains confidential information. Do not distribute without authorization.*
