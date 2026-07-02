"""
PromptWall Secret Finder (v8.3.2 - Deep Recon)
Scans discovered assets and JS files for hardcoded secrets and API keys.
"""

import math
import re
import logging
import requests
from src.core.stealth_client import stealth_client
from typing import List, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("intelligence.secrets")

class SecretFinder:
    """
    Identifies sensitive information in web assets with False Positive reduction.
    """
    
    # Blacklist of common false positive matches (Found in Moodle/etc)
    BLACKLIST = [
        "confirm", "cancel", "delete", "save", "edit", "update", "create", 
        "loading", "error", "success", "warning", "info", "admin", "login",
        "search", "close", "open", "true", "false", "null", "undefined",
        "default", "anonymous", "guest", "public", "private", "hidden"
    ]

    # Regex Patterns for Secrets
    PATTERNS = {
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"secret_key.*['\"]([0-9a-zA-Z+/]{40})['\"]",
        "Firebase URL": r"https://.*\.firebaseio\.com",
        "Generic API Key": r"(?:key|api|token|secret|pass|auth)[-_]?(?:key|api|token|secret|pass|auth)?[:=]\s*['\"]([0-9a-zA-Z]{16,})['\"]",
        "Database URL": r"(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+",
        "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "GitHub Personal Token": r"ghp_[0-9a-zA-Z]{36}"
    }

    def __init__(self, threads: int = 10):
        self.threads = threads
        self.found_secrets = []

    def calculate_entropy(self, data: str) -> float:
        """Calculates Shannon entropy to distinguish keys from normal text."""
        if not data: return 0
        prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def scan_content(self, source: str, content: str) -> List[Dict[str, str]]:
        """Scans a string for secret patterns with FP filtering."""
        local_secrets = []
        for name, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                secret_val = match.group(0)
                
                # FP Reduction 1: Blacklist check
                clean_val = re.sub(r"['\"]", "", secret_val.split(':')[-1].split('=')[-1]).strip()
                if clean_val.lower() in self.BLACKLIST:
                    continue
                
                # Filter out numbers only (often false positives)
                if clean_val.isdigit():
                    continue

                # FP Reduction 2: Entropy check (Keys usually have entropy > 3.8)
                entropy = self.calculate_entropy(clean_val)
                if entropy < 3.8 and name == "Generic API Key":
                    continue
                
                # Specific high-entropy check for Google Keys
                if name == "Google API Key" and entropy < 3.5:
                    continue

                # Obfuscate part of the secret for safety in logs
                obfuscated = secret_val[:6] + "..." + secret_val[-4:] if len(secret_val) > 10 else "***"
                
                local_secrets.append({
                    "source": source,
                    "type": name,
                    "match": obfuscated,
                    "entropy": round(entropy, 2),
                    "raw_context": content[max(0, match.start()-20) : min(len(content), match.end()+20)].strip()
                })
        return local_secrets

    def scan_url(self, url: str) -> List[Dict[str, str]]:
        """Downloads a URL and scans it using Stealth Client."""
        try:
            logger.debug(f"Fetching JS/Content from {url} (Stealth Mode)")
            res = stealth_client.get(url, timeout=20)
            if res and res.ok:
                return self.scan_content(url, res.text)
        except Exception as e:
            logger.warning(f"Failed to scan URL {url}: {e}")
        return []

    def scan_urls_concurrently(self, urls: List[str]) -> List[Dict[str, str]]:
        """Scans multiple URLs concurrently using ThreadPoolExecutor."""
        all_secrets = []
        if not urls:
            return all_secrets
            
        logger.info(f"Escaneando {len(urls)} URLs en paralelo para buscar secretos...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_secrets.extend(result)
                except Exception as e:
                    url = futures[future]
                    logger.warning(f"Error concurrentemente escaneando {url}: {e}")
        return all_secrets

# Global Instance helper
secret_finder = SecretFinder()
