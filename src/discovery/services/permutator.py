"""
Permutacion de Subdominios para Bug Bounty
Genera permutaciones logicas basadas en patrones reales de descubrimiento.
"""

from __future__ import annotations

import re
from typing import List

PREFIXES: List[str] = [
    "dev", "test", "staging", "backup", "old", "new", "beta", "alpha",
]

SUFFIXES: List[str] = [
    "dev", "test", "staging", "backup", "old", "api", "admin",
    "internal", "private",
]

COMPOUND_WORDS: List[str] = [
    "backend", "panel", "console", "admin", "portal", "dashboard",
    "manager", "api", "app", "service", "gateway", "proxy",
]

NUMBERS: List[str] = [str(i) for i in range(1, 11)] + [f"{i:02d}" for i in range(1, 11)]

RECENT_YEARS: List[str] = ["2024", "2025", "2026"]

CLOUD_REGIONS: List[str] = [
    "us-east-1", "us-west-1", "us-west-2", "eu-west-1",
    "eu-central-1", "ap-southeast-1", "ap-northeast-1",
]

CLOUD_PROVIDERS: List[str] = [
    "aws", "gcp", "azure", "do", "digitalocean",
]

ENVIRONMENTS: List[str] = ["staging", "dev", "qa", "uat"]

SERVICES: List[str] = [
    "mysql", "redis", "s3", "db", "api", "cdn",
    "cache", "queue", "worker", "websocket",
]

ARCHIVED_WORDS: List[str] = [
    "backup", "old", "archived", "deprecated",
    "removed", "unused", "legacy",
]


class Permutator:
    """Genera permutaciones de subdominios para descubrimiento en Bug Bounty.

    A partir de subdominios conocidos (ej: 'admin.example.com'), genera variaciones
    siguiendo patrones reales de bug bounty: prefijos, sufijos, numeros, entornos,
    regiones cloud, servicios, etc.

    Attributes:
        target_domain: Dominio objetivo (ej: 'example.com').
        max_permutations_per_seed: Maximo de permutaciones por subdominio semilla.
    """

    def __init__(self, target_domain: str, max_permutations_per_seed: int = 100) -> None:
        self.target_domain = target_domain.lower().strip()
        self.max_permutations_per_seed = max_permutations_per_seed

    def generate(self, seed_subdomains: List[str]) -> List[str]:
        """Genera todas las permutaciones a partir de subdominios semilla.

        Args:
            seed_subdomains: Lista de subdominios conocidos (ej: ['admin.example.com']).

        Returns:
            Lista de subdominios permutados sin duplicados.
        """
        seen: set[str] = set(seed_subdomains)
        result: List[str] = []

        for sub in seed_subdomains:
            sub = sub.lower().strip()
            if not sub:
                continue
            local = self._extract_local_part(sub)
            if not local:
                continue
            perms = self._permute(local, seen)
            result.extend(perms)

        return result

    def _extract_local_part(self, subdomain: str) -> str:
        suffix = f".{self.target_domain}"
        if subdomain.endswith(suffix):
            return subdomain[: -len(suffix)]
        if subdomain == self.target_domain:
            return ""
        return subdomain.split(".")[0]

    def _permute(self, local: str, seen: set[str]) -> List[str]:
        # ponytail: single-pass generation, per-word compound logic
        #          skipped if throughput matters, upgrade to concurrent generation
        candidates: List[str] = []
        add = candidates.append

        words = re.split(r"[-_.\s]+", local)
        first = words[0]

        # 1. Prefijos (saltear si el prefijo es igual a la palabra)
        for p in PREFIXES:
            if p != first:
                add(f"{p}-{local}")

        # 2. Sufijos (saltear si el sufijo es igual a la palabra)
        for s in SUFFIXES:
            if s != first:
                add(f"{local}-{s}")

        # 3. Palabras compuestas
        for w in COMPOUND_WORDS:
            if w != first:
                add(f"{first}-{w}")

        # 4. Numeros (simples y con ceros) + anos recientes
        for n in NUMBERS:
            add(f"{first}{n}")
        for y in RECENT_YEARS:
            add(f"{first}{y}")

        # 5. Variantes de separadores (si el local ya tiene mas de un token)
        if len(words) > 1:
            for sep in ("-", "_", "."):
                add(sep.join(words))
            add("".join(words))

        # 6. Entorno como subdominio padre
        for e in ENVIRONMENTS:
            add(f"{e}.{local}")

        # 7. Cloud: regiones + proveedores
        for r in CLOUD_REGIONS:
            add(f"{first}-{r}")
        for prov in CLOUD_PROVIDERS:
            add(f"{first}-{prov}")

        # 8. Servicios comunes
        for srv in SERVICES:
            if srv != first:
                add(f"{first}-{srv}")

        # 9. Archivado / legacy (ambas posiciones)
        for a in ARCHIVED_WORDS:
            if a != first:
                add(f"{a}-{first}")
                add(f"{first}-{a}")

        # Formatear con dominio target, deduplicar, cortar por limite
        result: List[str] = []
        for c in candidates:
            full = f"{c}.{self.target_domain}"
            if full not in seen:
                seen.add(full)
                result.append(full)
            if len(result) >= self.max_permutations_per_seed:
                break

        return result
