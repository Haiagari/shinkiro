"""
S3 Bucket Scanner - PromptWall
Generates candidate bucket names from a target domain and probes for exposed S3 buckets
across multiple regions. Detects public vs restricted buckets and attempts to list objects.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from xml.etree import ElementTree

import requests

logger = logging.getLogger("discovery.s3")

S3_REGIONS = (
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
)

KEYWORDS = (
    "backups", "data", "assets", "uploads", "media", "static",
    "files", "images", "videos", "documents", "logs", "config",
    "staging", "prod", "dev", "test", "public", "private",
    "storage", "archive", "tmp", "cache", "resources", "downloads",
    "cdn", "web", "app", "api", "bucket", "cloud", "content",
    "release", "backup", "www", "vault", "snapshots", "exports",
    "reports", "analytics", "metrics", "db", "database", "email",
)


class S3Scanner:
    """Scans for exposed S3 buckets derived from a target domain."""

    def __init__(self, max_workers: int = 20, timeout: int = 5) -> None:
        self.max_workers = max_workers
        self.timeout = timeout
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Bucket name generation
    # ------------------------------------------------------------------

    def _build_wordlist(self, domain: str) -> list[str]:
        """Generate >= 100 candidate bucket names from *domain*."""
        target = domain.split(".")[0].lower()
        domain_lower = domain.lower()
        tld_part = domain_lower.split(".")[1] if len(domain_lower.split(".")) > 1 else ""

        seen: set[str] = set()
        names: list[str] = []

        def add(raw: str) -> None:
            safe = raw.strip("-.").lower()
            if safe and 3 <= len(safe) <= 63 and safe not in seen:
                seen.add(safe)
                names.append(safe)

        # Pattern families — each yields ~40 names
        for kw in KEYWORDS:
            add(f"{target}-{kw}")
            add(f"{target}{kw}")
            add(f"{kw}-{target}")
            add(f"{kw}.{domain_lower}")
            add(f"{domain_lower}-{kw}")

        # With TLD part
        if tld_part:
            for kw in KEYWORDS:
                add(f"{target}-{kw}-{tld_part}")

        # Compound separators
        for sep in ("", "-", "."):
            add(f"{target}{sep}s3")
            add(f"{target}{sep}storage")
            add(f"{target}{sep}backup")

        # Raw domain variants
        add(target)
        add(f"{target}-prod")
        add(f"{target}-dev")
        add(domain_lower.replace(".", "-"))
        add(f"{domain_lower.replace('.', '-')}-backups")
        add(f"{domain_lower.replace('.', '-')}-storage")

        return names

    # ------------------------------------------------------------------
    # Single probe
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_listing(url: str, session: requests.Session, timeout: int) -> tuple[int, list[str]]:
        """Try to list objects. Returns (count, sample_keys)."""
        try:
            resp = session.get(
                f"{url}?max-keys=10",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code != 200 or "Contents" not in resp.text:
                return 0, []
            root = ElementTree.fromstring(resp.content)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            keys = [k.text for k in root.findall(".//s3:Key", ns) if k.text]
            return len(keys), keys[:10]
        except Exception:
            return 0, []

    def _probe_name(self, name: str) -> dict[str, Any] | None:
        """Probe *name* — hits the global endpoint first, then falls back to
        regional endpoints if the global one returns 404."""
        global_url = f"https://{name}.s3.amazonaws.com"

        try:
            resp = self._session.get(
                global_url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
        except (requests.ConnectionError, requests.Timeout):
            resp = None

        def _build_result(response: requests.Response, region: str) -> dict[str, Any]:
            status = "public" if response.status_code == 200 else "restricted"
            url = str(response.url)
            result: dict[str, Any] = {
                "bucket": name,
                "url": url,
                "status_code": response.status_code,
                "status": status,
                "region": region,
                "files_count": 0,
                "sample_files": [],
            }
            if response.status_code == 200:
                count, samples = self._parse_listing(url, self._session, self.timeout)
                result["files_count"] = count
                result["sample_files"] = samples
            s3_headers = {k: v for k, v in response.headers.items() if k.startswith("x-amz-")}
            if s3_headers:
                result["headers"] = s3_headers
            return result

        if resp is not None and resp.status_code != 404:
            region = "us-east-1"
            if resp.history:
                for h in resp.history:
                    loc = h.headers.get("Location", "")
                    for r in S3_REGIONS:
                        if r in loc:
                            region = r
                            break
            return _build_result(resp, region)

        for region in S3_REGIONS:
            if region == "us-east-1":
                continue
            for tmpl in (f"https://{name}.s3-{region}.amazonaws.com",
                         f"https://{name}.s3.{region}.amazonaws.com"):
                try:
                    r = self._session.get(
                        tmpl, timeout=self.timeout, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                except (requests.ConnectionError, requests.Timeout):
                    continue
                if r.status_code != 404:
                    return _build_result(r, region)

        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target_domain: str) -> list[dict[str, Any]]:
        """
        Scan *target_domain* for exposed S3 buckets.

        Returns a list of dicts, one per discovered bucket::

            {
                "bucket": "unitru-backups",
                "url": "https://unitru-backups.s3.amazonaws.com",
                "status_code": 200,
                "status": "public" | "restricted",
                "region": "us-east-1",
                "files_count": 42,
                "sample_files": ["img001.jpg", ...],
            }
        """
        wordlist = self._build_wordlist(target_domain)
        logger.info(
            "S3 scanning %s with %d candidates across %d regions",
            target_domain, len(wordlist), len(S3_REGIONS),
        )

        seen: set[str] = set()
        results: list[dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            fut_map = {pool.submit(self._probe_name, name): name for name in wordlist}
            for future in as_completed(fut_map):
                result = future.result()
                if result and result["bucket"] not in seen:
                    seen.add(result["bucket"])
                    results.append(result)

        results.sort(key=lambda r: (r["status_code"], r["bucket"]))
        logger.info("S3 scan for %s: %d bucket(s) found", target_domain, len(results))
        return results
