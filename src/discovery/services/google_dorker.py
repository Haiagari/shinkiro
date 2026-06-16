"""
Google Dorking - OzyRecon v9.0
Ejecuta Google Dorks sobre un dominio target mediante scraping de resultados.
Sin depender de la API de Google.
"""

import logging
import re
import time
from typing import Any
from urllib.parse import quote_plus

import requests

from src.utils import log

logger = logging.getLogger("discovery.google_dorker")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

RATE_LIMIT = 3.0
BLOCK_WAIT = 30.0
MAX_RETRIES = 1
TIMEOUT = 15

DORKS: list[dict[str, str]] = [
    {"dork": 'intitle:"index of"', "category": "exposed_document"},
    {"dork": "intitle:login", "category": "admin_panel"},
    {"dork": "inurl:admin", "category": "admin_panel"},
    {"dork": "inurl:wp-admin", "category": "admin_panel"},
    {"dork": "ext:php intitle:phpinfo", "category": "debug_page"},
    {"dork": "ext:sql | ext:bak | ext:old | ext:swp", "category": "exposed_document"},
    {"dork": "inurl:wp-config", "category": "config_leak"},
    {"dork": "inurl:apidocs | inurl:api-docs | inurl:swagger", "category": "exposed_document"},
    {"dork": "intitle:dashboard", "category": "admin_panel"},
    {"dork": "inurl:gitlab | inurl:jenkins | inurl:jira", "category": "admin_panel"},
    {"dork": '"confidential" | "internal use only"', "category": "exposed_document"},
    {"dork": "inurl:debug | inurl:test | inurl:staging | inurl:dev", "category": "debug_page"},
    {'dork': 'intitle:"Directory Listing"', "category": "exposed_document"},
    {"dork": '"s3.amazonaws.com"', "category": "cloud_bucket"},
    {"dork": '".amazonaws.com" | "blob.core.windows.net"', "category": "cloud_bucket"},
    {"dork": 'ext:pdf "confidential" | "proprietary"', "category": "exposed_document"},
    {"dork": "inurl:phpmyadmin | inurl:phpPgAdmin | inurl:adminer", "category": "admin_panel"},
    {"dork": "inurl:.env | inurl:.git/config", "category": "config_leak"},
    {"dork": "ext:xml | ext:conf | ext:cfg | ext:yml", "category": "config_leak"},
    {"dork": "inurl:backup | inurl:dump | inurl:back-end", "category": "exposed_document"},
    {'dork': 'intitle:"error" | intitle:"warning" | intitle:"notice"', "category": "debug_page"},
    {"dork": 'intitle:"login" intitle:"sign in"', "category": "admin_panel"},
    {"dork": "inurl:redir | inurl:redirect | inurl:return_url", "category": "suspicious"},
    {"dork": "ext:log | ext:txt password | ext:txt passwd", "category": "exposed_document"},
    {"dork": 'inurl:".aws" | inurl:".azure" | inurl:"credentials"', "category": "config_leak"},
    {"dork": "inurl:dashboard | inurl:console | inurl:panel", "category": "admin_panel"},
    {"dork": "intitle:grafana | intitle:kibana | intitle:prometheus", "category": "admin_panel"},
    {"dork": 'ext:csv "email" | ext:xls "email"', "category": "exposed_document"},
    {"dork": "inurl:webshell | inurl:cmd | inurl:exec", "category": "suspicious"},
    {"dork": "inurl:server-status | inurl:server-info", "category": "debug_page"},
]


class GoogleDorker:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _search(self, dork: str) -> str | None:
        url = f"https://www.google.com/search?q={quote_plus(dork)}&hl=en&num=10"
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.get(url, timeout=TIMEOUT)
                if resp.status_code == 429 or resp.status_code == 503:
                    logger.warning("Google bloqueó la request (HTTP %s). Esperando %ss...", resp.status_code, BLOCK_WAIT)
                    time.sleep(BLOCK_WAIT)
                    continue
                if resp.status_code == 200:
                    return resp.text
                logger.debug("HTTP %s para dork: %s", resp.status_code, dork)
                return None
            except requests.RequestException as e:
                logger.warning("Error en request para dork '%s': %s", dork, e)
                if attempt < MAX_RETRIES:
                    time.sleep(BLOCK_WAIT)
        return None

    @staticmethod
    def _parse_results(html: str) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        # Google SERP pattern: <a href="..."> with <h3> for titles inside
        # Fall back to broader patterns if the main one fails
        blocks = re.split(r'(?=<div[^>]*class="[^"]*g[^"]*")', html)
        if len(blocks) < 2:
            blocks = re.split(r'(?=<div[^>]*class="[^"]*[Bb]lock[^"]*")', html)
        if len(blocks) < 2:
            blocks = [html]

        seen_urls: set[str] = set()

        for block in blocks:
            url_match = re.search(r'href="(https?://[^"]+)"', block)
            title_match = re.search(r'<h3[^>]*>(.*?)</h3>', block, re.DOTALL)
            snippet_match = re.search(r'<div[^>]*class="[^"]*[Vv]i[^"]*"[^>]*>(.*?)</div>', block, re.DOTALL)

            if not url_match:
                continue

            url = url_match.group(1)
            # Filter out Google's own links
            if "google.com/" in url and "search?" not in url:
                continue
            if url in seen_urls:
                continue
            seen_urls.add(url)

            title = ""
            if title_match:
                title = re.sub(r'<[^>]+>', '', title_match.group(1)).strip()

            snippet = ""
            if snippet_match:
                snippet = re.sub(r'<[^>]+>', '', snippet_match.group(1)).strip()
                snippet = re.sub(r'\s+', ' ', snippet)[:300]

            results.append({"url": url, "title": title, "snippet": snippet})

        return results

    def dork(self, target_domain: str) -> list[dict[str, Any]]:
        if not target_domain:
            log("GoogleDorker: target_domain vacío", "warning")
            return []

        log(f"Google Dorking iniciado para: {target_domain}", "info")
        findings: list[dict[str, Any]] = []
        total = len(DORKS)

        for i, entry in enumerate(DORKS, 1):
            full_dork = f"site:{target_domain} {entry['dork']}"
            logger.debug("[%d/%d] Ejecutando dork: %s", i, total, full_dork)

            html = self._search(full_dork)

            if html is None:
                logger.debug("Sin resultados para: %s", full_dork)
                time.sleep(RATE_LIMIT)
                continue

            parsed = self._parse_results(html)

            for res in parsed:
                findings.append({
                    "url": res["url"],
                    "title": res["title"],
                    "snippet": res["snippet"],
                    "dork": full_dork,
                    "category": entry["category"],
                })

            if parsed:
                log(f"[{i}/{total}] {entry['category']}: {len(parsed)} resultado(s) con '{full_dork}'", "success")
            else:
                logger.debug("[%d/%d] Sin resultados parseables en '%s'", i, total, full_dork)

            time.sleep(RATE_LIMIT)

        log(f"Google Dorking completado: {len(findings)} hallazgos para {target_domain}", "info")
        return findings
