"""
CVE Correlation Module.
Maps detected software versions to known CVEs via NVD API.
"""

import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class CVEEntry:
    id: str
    description: str
    severity: str
    cvss_score: Optional[float]
    published: str
    exploit_available: bool = False


# Mapping of tech names to CPE search patterns
TECH_CPE_MAP = {
    "apache_http_server": "apache:http_server",
    "php": "php:php",
    "wordpress": "wordpress:wordpress",
    "nginx": "nginx:nginx",
    "mysql": "mysql:mysql",
    "joomla": "joomla:joomla",
    "moodle": "moodle:moodle",
    "laravel": "laravel:laravel",
    "glpi": "glpi:glpi",
    "koha": "koha:koha",
}


class CVEChecker:
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path("/tmp/promptwall_cve_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _nvd_api_url(self, cpe: str, version: str) -> str:
        # CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        parts = cpe.split(":")
        vendor = parts[0]
        product = parts[1]
        return (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?cpeName=cpe:2.3:a:{vendor}:{product}:{version}"
            f"&resultsPerPage=20"
        )

    def lookup(self, tech_name: str, version: str) -> list[CVEEntry]:
        cache_key = f"{tech_name}_{version}".replace(" ", "_").replace(".", "_")
        cache_file = self.cache_dir / f"{cache_key}.json"

        if cache_file.exists():
            return self._parse_cves(json.loads(cache_file.read_text()))

        normalized = tech_name.lower().replace(" ", "_").replace("-", "_")
        cpe_key = None
        for key in TECH_CPE_MAP:
            if key in normalized or normalized in key:
                cpe_key = TECH_CPE_MAP[key]
                break

        if not cpe_key:
            return []

        url = self._nvd_api_url(cpe_key, version)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PromptWall/9.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read())
            cache_file.write_text(json.dumps(data, indent=2))
            return self._parse_cves(data)
        except Exception:
            return []

    def _parse_cves(self, data: dict) -> list[CVEEntry]:
        results = []
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns[:10]:
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            severity = "UNKNOWN"

            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_key in metrics:
                    metric = metrics[metric_key][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d["value"][:200]
                    break

            results.append(CVEEntry(
                id=cve.get("id", ""),
                description=desc,
                severity=severity,
                cvss_score=cvss,
                published=cve.get("published", "")[:10],
            ))
        return results

    def batch_lookup(self, tech_versions: dict[str, str]) -> dict[str, list[CVEEntry]]:
        results = {}
        for tech, version in tech_versions.items():
            cves = self.lookup(tech, version)
            if cves:
                results[tech] = cves
        return results
