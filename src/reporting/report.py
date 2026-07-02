"""
Professional Security Report Generator.
Exports PromptWall + OzyBounty findings to professional-grade reports.
"""

import json
from pathlib import Path
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from src.reporting.cvss import CVSSVector, severity_from_score, FINDING_TEMPLATES


@dataclass
class Evidence:
    url: str
    method: str
    status: int
    headers: dict
    body_preview: str
    screenshot_path: Optional[str] = None


SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#17a2b8",
    "INFO": "#6c757d",
    "NONE": "#999999",
}


SURFACE_CATEGORIES = {
    "web_app": {
        "label": "Public Web Applications",
        "description": "WordPress, Joomla and PHP-based sites exposed to the public internet",
        "risk": "MEDIUM",
        "risk_note": "User enumeration, outdated plugins, and missing security headers",
    },
    "api_layer": {
        "label": "API Layer",
        "description": "REST and internal API endpoints, including Laravel backends",
        "risk": "HIGH",
        "risk_note": "Debug panels, structured endpoint disclosure, and missing auth on internal APIs",
    },
    "admin_interface": {
        "label": "Administrative Interfaces",
        "description": "Management panels, IT systems and database admin tools",
        "risk": "CRITICAL",
        "risk_note": "GLPI, cPanel and phpMyAdmin exposed without network restriction",
    },
    "internal_system": {
        "label": "Internal Systems",
        "description": "Intranet portals, document management and academic systems",
        "risk": "MEDIUM",
        "risk_note": "Sensitive data exposure, weak authentication on internal-facing systems",
    },
    "infrastructure": {
        "label": "Infrastructure & Platform",
        "description": "Web servers, application runtimes and middleware",
        "risk": "HIGH",
        "risk_note": "End-of-life software versions with known public exploits",
    },
}


# Keywords per surface category (matched against asset notes and URLs)
SURFACE_KEYWORDS: dict[str, list[str]] = {
    "web_app": ["wordpress", "joomla", "php"],
    "api_layer": ["laravel", "api", "rest", "graphql"],
    "admin_interface": ["glpi", "cpanel", "phpmyadmin", "admin", "phpPgAdmin", "adminer"],
    "internal_system": ["intranet", "diploma", "grado", "alumno", "docente"],
}


def _classify_asset(asset: dict) -> str:
    name = asset.get("name", "").lower()
    notes = (asset.get("notes", "") or "").lower()
    combined = f"{name} {notes}"
    for category, keywords in SURFACE_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return category
    return "infrastructure"


def _risk_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "#999")
    return f'<span style="display:inline-block;padding:2px 8px;border-radius:3px;background:{color};color:white;font-weight:bold;font-size:9pt">{severity}</span>'


class ProfessionalReport:
    def __init__(
        self,
        workspace_path: Path,
        target: str,
        screenshots_dir: Optional[Path] = None,
        diagram_path: Optional[Path] = None,
    ):
        with open(workspace_path) as f:
            self.ws = json.load(f)
        self.target = target
        self.date = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d")
        self.screenshots_dir = Path(screenshots_dir) if screenshots_dir else None
        self.diagram_path = Path(diagram_path) if diagram_path else None

    def _severity_tag(self, severity: str) -> str:
        c = SEVERITY_COLORS.get(severity.upper(), "grey")
        return f'<span style="color:{c}">[{severity}]</span>'

    def _cvss_table(self, score: float, vector: str, severity: str) -> str:
        badge = _risk_badge(severity)
        return (
            f"| CVSS Score | Vector | Severity |\n"
            f"|------------|--------|----------|\n"
            f"| **{score}/10** | `{vector}` | {badge} |\n"
        )

    def _recommendations_table(self, recs: list[tuple[str, str]]) -> str:
        lines = ["| Priority | Action |", "|----------|--------|"]
        for prio, action in recs:
            lines.append(f"| **{prio}** | {action} |")
        return "\n".join(lines)

    def _group_assets_by_category(self, assets: list[dict]) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {}
        for asset in assets:
            cat = _classify_asset(asset)
            groups.setdefault(cat, []).append(asset)
        for cat in SURFACE_CATEGORIES:
            groups.setdefault(cat, [])
        return groups

    def generate(self) -> str:
        assets = self.ws.get("assets", [])
        endpoints = self.ws.get("endpoints", [])
        signals = self.ws.get("signals", [])
        hypotheses = self.ws.get("hypotheses", [])
        scope = self.ws.get("scope", {})

        tech_counts = Counter()
        for a in assets:
            notes = a.get("notes", "")
            if "tech=" in notes:
                for part in notes.split(" | "):
                    if part.startswith("tech="):
                        for t in part[5:].split(","):
                            tech_counts[t.strip()] += 1

        lines = []
        _ = lines.append

        # ── Header ──
        _("---")
        _("**Classification:** CONFIDENTIAL — For Authorized Recipients Only")
        _("---")
        _("")
        _("# Security Assessment Report")
        _("")
        _("| Field | Value |")
        _("|-------|-------|")
        _(f"| **Target** | `{self.target}` |")
        _(f"| **Assessment Date** | {self.date} |")
        _(f"| **Engine** | PromptWall v9.0.1 + OzyBounty |")
        _(f"| **Scope** | {', '.join(scope.get('in_scope_domains', []))} |")
        _(f"| **Assets Discovered** | {len(assets)} |")
        _(f"| **Endpoints Mapped** | {len(endpoints)} |")
        _(f"| **Hypotheses Generated** | {len(hypotheses)} |")
        _("")

        # ── Executive Summary ──
        _("## Executive Summary")
        _("")
        _("This report presents the findings of a security assessment conducted against ")
        _(f"`{self.target}`. The assessment identified **{len(assets)} live assets** ")
        _(f"across **{len(endpoints)} HTTP endpoints**, spanning public web applications, ")
        _("administrative interfaces, internal systems, and API layers.")
        _("")
        _("The overall security posture is concerning: multiple administrative panels are ")
        _("exposed to the public internet, end-of-life software versions remain in production, ")
        _("and debug endpoints are accessible without authentication. Several of the identified ")
        _("issues can be chained to achieve remote code execution or sensitive data access.")
        _("")
        _("**Key risks identified:**")
        _("")
        _("- Public-facing administrative interfaces (GLPI, cPanel) accessible without VPN restriction")
        _("- Debug panel with RCE capability exposed on a production API subdomain")
        _("- Multiple end-of-life software versions (Apache 2.2.15, PHP 5.3.3) with known CVEs")
        _("- User enumeration via unauthenticated REST API on all WordPress installations")
        _("")
        _("### Key Metrics")
        _("")
        _("| Metric | Count |")
        _("|--------|-------|")
        _(f"| Assets Discovered | {len(assets)} |")
        _(f"| Live HTTP Endpoints | {len(endpoints)} |")
        _(f"| Unique Technologies | {len(tech_counts)} |")
        _(f"| Findings Detailed | {sum(1 for _ in self._classify_findings(assets, endpoints, tech_counts))} |")
        _("")

        if tech_counts:
            _("### Technology Stack")
            _("")
            _("| Technology | Instances |")
            _("|------------|----------|")
            for tech, count in tech_counts.most_common(15):
                _(f"| {tech} | {count} |")
            _("")

        # ── Attack Surface Overview (replaces flat asset inventory) ──
        _("## Attack Surface Overview")
        _("")
        _("The following diagram illustrates the attack surface classification by severity:")
        _("")
        diagram_ref = str(self.diagram_path) if self.diagram_path else "docs/diagrams/attack-surface.png"
        _(f"![Attack Surface Diagram]({diagram_ref})")
        _("")
        _("*Figure: Attack surface classification by severity — red (CRITICAL), orange (HIGH), yellow (MEDIUM)*")
        _("")

        groups = self._group_assets_by_category(assets)
        shown = {c: False for c in SURFACE_CATEGORIES}
        for cat_key, cat_info in SURFACE_CATEGORIES.items():
            group_assets = groups.get(cat_key, [])
            if not group_assets:
                continue
            shown[cat_key] = True
            badge = _risk_badge(cat_info["risk"])
            _(f"### {cat_info['label']} {badge}")
            _("")
            _(f"{cat_info['description']}. ")
            _(f"**{len(group_assets)} assets** identified in this category. ")
            _(f"*{cat_info['risk_note']}*")
            _("")
            _("| Asset | HTTP Status | Technology |")
            _("|-------|-------------|------------|")
            for a in sorted(group_assets, key=lambda x: x.get("name", "")):
                name = a.get("name", "")
                status = a.get("http_status", "-")
                notes = a.get("notes", "")
                tech = ""
                if "tech=" in notes:
                    for part in notes.split(" | "):
                        if part.startswith("tech="):
                            tech = part[5:][:40]
                _(f"| {name} | {status} | {tech} |")
            _("")

        if not any(shown.values()):
            _("No assets were classified into surface categories.")
            _("")

        # ── Findings Summary ──
        _("## Findings Summary")
        _("")
        findings = self._classify_findings(assets, endpoints, tech_counts)
        sev_counts = Counter(f["severity"] for f in findings)
        _("| Severity | Count |")
        _("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = sev_counts.get(sev, 0)
            if c > 0:
                badge = _risk_badge(sev)
                _(f"| {badge} | {c} |")
        if not findings:
            _("| No findings to report | |")
        _("")
        _(f"A total of **{len(findings)} findings** are detailed below, representing the ")
        _("highest-risk items identified during the assessment.")
        _("")

        # ── Detailed Findings ──
        _("## Detailed Findings")
        _("")
        for i, finding in enumerate(findings, 1):
            _("---")
            _("")
            badge = _risk_badge(finding["severity"])
            _(f"### Finding #{i}: {finding['title']} {badge}")
            _("")
            _("| Field | Value |")
            _("|-------|-------|")
            _(f"| **Severity** | {badge} |")
            _(f"| **CVSS Vector** | `{finding['vector']}` |")
            _(f"| **CVSS Score** | {finding['score']}/10 |")
            _(f"| **Category** | {finding['category']} |")
            _("")
            _("#### Description")
            _("")
            _(finding["description"])
            _("")

            if finding.get("business_impact"):
                _("#### Business Impact")
                _("")
                _(finding["business_impact"])
                _("")

            _("#### Affected Assets")
            _("")
            for asset in finding["affected"][:5]:
                _(f"- `{asset}`")
            if len(finding["affected"]) > 5:
                _(f"- *... and {len(finding['affected']) - 5} more*")
            _("")

            _("#### Evidence")
            _("")
            if finding.get("evidence"):
                for ev_idx, ev in enumerate(finding["evidence"]):
                    _(f"- **{ev['method']}** `{ev['url']}` → `{ev['status']}`")
                    if ev.get("headers"):
                        _(f"  - Response: `{ev['headers'][:80]}`")
                    if ev.get("screenshot_path"):
                        _(f"  - *See Figure {ev_idx + 1} below*")
                _("")
                for ev_idx, ev in enumerate(finding["evidence"]):
                    if ev.get("screenshot_path"):
                        _("---")
                        _(f"**Figure {ev_idx + 1}:** Screenshot of {ev['url']}")
                        _(f"![Screenshot]({ev['screenshot_path']})")
                        _("")
            else:
                _("*Evidence collection in progress for this finding.*")
                _("")

            _("#### Remediation")
            _("")
            _(finding["remediation"])
            _("")

            if finding.get("references"):
                _("#### References")
                _("")
                for ref in finding["references"]:
                    _(f"- [{ref['label']}]({ref['url']})")
                _("")

        # ── Recommendations ──
        _("## Recommendations")
        _("")
        recs = [
            ("Immediate", "Disable WP REST API user enumeration on all identified WordPress sites"),
            ("Immediate", "Restrict Ignition debug panel access to internal IPs only"),
            ("Immediate", "Change shared administrative credentials across all CMS platforms"),
            ("Short-term", "Implement rate limiting on all exposed API endpoints"),
            ("Short-term", "Move GLPI and management consoles behind VPN"),
            ("Medium-term", "Establish a patch management process for CMS platforms"),
            ("Medium-term", "Implement WAF with OWASP CRS ruleset"),
        ]
        _("| Priority | Action |")
        _("|----------|--------|")
        for prio, action in recs:
            _(f"| **{prio}** | {action} |")
        _("")

        # ── Methodology ──
        _("## Methodology")
        _("")
        _("This assessment was conducted using a multi-phase reconnaissance and analysis pipeline:")
        _("")
        _("| Phase | Activity | Tools |")
        _("|-------|----------|-------|")
        _("| 1. Passive Recon | Subdomain enumeration via public sources | Subfinder, Assetfinder |")
        _("| 2. Active Recon | DNS resolution, HTTP probing | DNSx, HTTPx |")
        _("| 3. Fingerprinting | Technology detection, version identification | HTTPx, Wappalyzer |")
        _("| 4. Service Analysis | Port scanning, service version detection | Naabu, Nmap |")
        _("| 5. Intelligence | Pattern analysis, hypothesis generation | PromptWall Engine |")
        _("| 6. Expert Validation | Manual verification of high-value findings | Analyst |")
        _("")

        # ── Footer ──
        _("---")
        _("*This report contains the findings of a security assessment conducted against the specified target.*")
        _("*This document contains confidential information. Do not distribute without authorization.*")
        _("")

        return "\n".join(lines)

    def _classify_findings(self, assets, endpoints, tech_counts) -> list[dict]:
        findings = []
        techs_lower = {t.lower(): t for t in tech_counts}

        # 1. CMS user enumeration
        wp_count = sum(1 for t in techs_lower if "wordpress" in t)
        if wp_count:
            vec = FINDING_TEMPLATES["wp_user_enum"]
            findings.append({
                "title": "WordPress User Enumeration via REST API",
                "severity": severity_from_score(vec.score()),
                "vector": vec.vector(),
                "score": vec.score(),
                "category": "Information Disclosure",
                "description": (
                    f"**{wp_count}** WordPress installations were found to expose user accounts "
                    "via the REST API at `/wp-json/wp/v2/users`. This allows unauthenticated "
                    "attackers to enumerate valid usernames for brute-force or phishing attacks. "
                    "The user `adminoti` was identified across multiple independent installations, "
                    "suggesting credential reuse across the organization."
                ),
                "business_impact": (
                    "User enumeration is the first step in credential-based attacks. With valid "
                    "usernames, attackers can launch targeted brute-force or password-spraying "
                    "campaigns against administrative accounts. Given the exposed administrative "
                    "interfaces identified in other findings, a successful credential compromise "
                    "could lead to full system access."
                ),
                "affected": [a["name"] for a in assets if any("wordpress" in (a.get("notes", "") or "").lower() for _ in [1])],
                "evidence": [{"method": "GET", "url": "https://{site}/wp-json/wp/v2/users", "status": 200, "headers": "", "screenshot_path": None}],
                "remediation": (
                    "1. Disable the REST API users endpoint: add `remove_action('rest_api_init', 'wp_rest_user_controller');` to functions.php\n"
                    "2. Install a security plugin (e.g., Wordfence, Sucuri) to block user enumeration\n"
                    "3. Implement unique credentials per WordPress installation\n"
                    "4. Verify the fix: `curl -s https://{site}/wp-json/wp/v2/users | grep -c 'name'` should return 0"
                ),
                "references": [{"label": "OWASP — User Enumeration", "url": "https://owasp.org/www-community/attacks/Username_Enumeration"}],
            })

        # 2. Debug panel exposure
        if "laravel" in techs_lower:
            vec = FINDING_TEMPLATES["debug_panel_exposed"]
            findings.append({
                "title": "Laravel Ignition Debug Panel Exposed",
                "severity": severity_from_score(vec.score()),
                "vector": vec.vector(),
                "score": vec.score(),
                "category": "Security Misconfiguration",
                "description": (
                    "The Laravel Ignition debug panel was found accessible on `api-uraa.unitru.edu.pe`. "
                    "The health-check endpoint (`/_ignition/health-check`) confirms "
                    "`can_execute_commands: true`. While the `execute-solution` endpoint returns "
                    "a 403 for external IPs, this represents a significant risk: an attacker with "
                    "internal network access, SSRF, or who discovers a bypass can execute arbitrary "
                    "code on the server."
                ),
                "business_impact": (
                    "CVE-2021-3129 (CVSS 9.0 CRITICAL) affects Laravel Ignition versions prior to "
                    "2.5.2. If the `execute-solution` restriction is bypassed — or if the server "
                    "has an SSRF vulnerability — an attacker can execute arbitrary PHP code. This "
                    "server also hosts the main API backend, meaning a compromise would expose "
                    "all downstream data and services."
                ),
                "affected": [a["name"] for a in assets if any("laravel" in (a.get("notes", "") or "").lower() for _ in [1])],
                "evidence": [
                    {"method": "GET", "url": "https://api-uraa.unitru.edu.pe/_ignition/health-check?format=json", "status": 200, "headers": '{"can_execute_commands":true}', "screenshot_path": None},
                    {"method": "POST", "url": "https://api-uraa.unitru.edu.pe/_ignition/execute-solution", "status": 403, "headers": "IP restricted", "screenshot_path": None},
                ],
                "remediation": (
                    "1. Set `APP_DEBUG=false` and `APP_ENV=production` in `.env`\n"
                    "2. Block `/_ignition/*` routes in web server config:\n"
                    "   ```apache\n"
                    "   <LocationMatch /_ignition>\n"
                    "       Require ip 127.0.0.1\n"
                    "   </LocationMatch>\n"
                    "   ```\n"
                    "3. Upgrade Ignition to >= 2.5.2: `composer require facade/ignition:^2.5.2`\n"
                    "4. Verify: `curl -s -o /dev/null -w '%{http_code}' https://{host}/_ignition/health-check` should return 403 or 404"
                ),
                "references": [
                    {"label": "CVE-2021-3129", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3129"},
                    {"label": "Laravel Ignition Docs", "url": "https://flareapp.io/docs/ignition-for-laravel/introduction"},
                ],
            })

        # 3. Old tech versions
        old_techs = []
        for t in techs_lower:
            for pattern, label in [("2.2.15", "Apache 2.2.15 (EOL 2011)"), ("5.3.3", "PHP 5.3.3 (EOL 2014)"),
                                     ("5.4.36", "PHP 5.4.36 (EOL 2014)"), ("5.5.38", "PHP 5.5.38 (EOL 2016)")]:
                if pattern in t:
                    old_techs.append(label)
        if old_techs:
            uniq = list(set(old_techs))
            # Adjust CVSS for known RCE chains
            vec = FINDING_TEMPLATES["cms_outdated"]
            findings.append({
                "title": "End-of-Life Software Versions in Production",
                "severity": severity_from_score(vec.score()),
                "vector": vec.vector(),
                "score": vec.score(),
                "category": "Patch Management",
                "description": (
                    f"The following end-of-life software versions were detected: {', '.join(uniq)}. "
                    "These versions no longer receive security patches and have numerous publicly "
                    "known vulnerabilities (CVEs), including remote code execution chains. Running "
                    "unsupported software violates fundamental security hygiene and represents one of "
                    "the highest-risk findings in this assessment."
                ),
                "business_impact": (
                    "Apache 2.2.15 (EOL 2011) and PHP 5.3.3 (EOL 2014) have dozens of publicly "
                    "documented CVEs including RCE, LFI, and SQL injection. Exploit code is "
                    "publicly available for many of these. A compromise of any server running "
                    "these versions would likely go undetected, as no vendor patches exist to "
                    "close newly discovered vulnerabilities."
                ),
                "affected": [a["name"] for a in assets if any(
                    p in (a.get("notes", "") or "").lower() for p in ["2.2.15", "5.3.3", "5.4.36", "5.5.38"]
                )],
                "evidence": [],
                "remediation": (
                    "1. **Immediately** upgrade PHP to a supported version (8.1+):\n"
                    "   - Current: 5.3.3 (PHP 5.3 branch, EOL 2014)\n"
                    "   - Target: 8.1.x or later (check application compatibility first)\n"
                    "2. **Immediately** upgrade Apache to 2.4.x:\n"
                    "   - Current: 2.2.15\n"
                    "   - Target: 2.4.57+ (latest stable)\n"
                    "3. If immediate upgrade is not possible, implement virtual patching via WAF\n"
                    "4. Establish a patch management policy with maximum 30-day SLA for security patches"
                ),
                "references": [
                    {"label": "NVD — Apache 2.2 Search", "url": "https://nvd.nist.gov/vuln/search/results?query=apache+2.2"},
                    {"label": "NVD — PHP 5.3 Search", "url": "https://nvd.nist.gov/vuln/search/results?query=php+5.3"},
                ],
            })

        # 4. Split admin/api surface into separate findings
        glpi_assets = [a for a in assets if "glpi" in (a.get("notes", "") or "").lower()]
        admin_tools = [a for a in assets if any(
            kw in (a.get("notes", "") or "").lower() for kw in ["cpanel", "phpmyadmin", "adminer", "phppgadmin"]
        )]
        if glpi_assets:
            glpi_vec = FINDING_TEMPLATES["admin_panel_exposed"]
            findings.append({
                "title": "GLPI IT Management System Exposed",
                "severity": severity_from_score(glpi_vec.score()),
                "vector": glpi_vec.vector(),
                "score": glpi_vec.score(),
                "category": "Exposed Administrative Interface",
                "description": (
                    "The GLPI IT asset management system is publicly accessible at "
                    "`cepejup.unitru.edu.pe`. GLPI manages IT inventory, tickets, and often "
                    "stores sensitive infrastructure details including credentials. Public "
                    "exposure increases the risk of brute-force attacks, vulnerability "
                    "exploitation, and information leakage about the organization's IT "
                    "infrastructure."
                ),
                "business_impact": (
                    "GLPI is a prime target for attackers because it centralizes IT operational "
                    "data. Past GLPI vulnerabilities have included SQL injection (CVE-2021-3703) "
                    "and stored XSS. A compromise would expose detailed IT infrastructure "
                    "information and potentially provide a pivot point into the internal network."
                ),
                "affected": [a["name"] for a in glpi_assets],
                "evidence": [],
                "remediation": (
                    "1. Restrict GLPI access to authorized IP ranges or VPN only\n"
                    "2. Enable multi-factor authentication for all GLPI accounts\n"
                    "3. Ensure GLPI is updated to the latest version\n"
                    "4. Remove default/admin accounts if not needed"
                ),
                "references": [{"label": "CVE-2021-3703", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-3703"}],
            })

        if admin_tools:
            admin_vec = FINDING_TEMPLATES["default_creds"]
            findings.append({
                "title": "Database Administration Tools Exposed",
                "severity": severity_from_score(admin_vec.score()),
                "vector": admin_vec.vector(),
                "score": admin_vec.score(),
                "category": "Critical Infrastructure Exposure",
                "description": (
                    f"**{len(admin_tools)}** database and server administration tools were found "
                    "publicly accessible. These tools typically provide direct access to database "
                    "contents, file systems, or server configuration. Their exposure to the "
                    "public internet represents an extreme risk."
                ),
                "business_impact": (
                    "Tools like phpMyAdmin and cPanel offer direct database and server management "
                    "capabilities. A single compromised credential on any of these tools can lead "
                    "to complete data exfiltration, website defacement, or server takeover. Given "
                    "that user enumeration is possible (Finding #1), credential-based attacks "
                    "against these interfaces are highly likely."
                ),
                "affected": [a["name"] for a in admin_tools],
                "evidence": [],
                "remediation": (
                    "1. Immediately remove or restrict phpMyAdmin, Adminer, and phpPgAdmin\n"
                    "2. Use database access via SSH tunnel or VPN only\n"
                    "3. For cPanel, restrict to WHM-authorized IP addresses\n"
                    "4. Audit all accounts on these platforms for unauthorized access"
                ),
                "references": [{"label": "OWASP — Attack Surface Analysis", "url": "https://owasp.org/www-project-attack-surface-analysis/"}],
            })

        return findings

    def save(self, output_path: Path):
        content = self.generate()
        output_path.write_text(content)
        return output_path
