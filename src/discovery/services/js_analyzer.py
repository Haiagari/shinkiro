"""
JSAnalyzer — Extracción de endpoints desde JavaScript.

Extrae rutas, métodos HTTP y parámetros usando regex.
Detecta fetch, axios, $.ajax, router.*, ky y strings literales de ruta.
Normaliza UUIDs/números como {id} para agrupar rutas similares.
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger("discovery.js_analyzer")

_RE_FUNC_CALL = re.compile(
    r"([a-zA-Z_$][\w$.]*)"
    r"\s*[(]\s*"
    r'(?:"([^"]+)"|\'([^\']+)\')'
)

_RE_OBJ_URL = re.compile(
    r'(?:(?:url|path)\s*:\s*)'
    r'(?:"([^"]+)"|\'([^\']+)\')'
)

_RE_OBJ_METHOD = re.compile(
    r'(?:method|type)\s*:\s*'
    r'(?:"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"|\'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\')',
    re.IGNORECASE,
)

_RE_PARAMS_BLOCK = re.compile(r"(?:params|data|body)\s*:\s*\{(.*?)\}", re.DOTALL)

_RE_PATH_LITERAL = re.compile(
    r'(?:"|\')'
    r'(/'
    r'(?:api|v[12]|v3|admin|graphql|rest|auth|oauth|webhook'
    r'|health|metrics|status|static|assets|upload|download'
    r'|ws|wss|sockjs|socket)'
    r'(?:/[a-zA-Z0-9_\-./{}[\]?&=]*)?'
    r')'
    r'(?:"|\')',
    re.IGNORECASE,
)

_RE_FULL_URL = re.compile(
    r'(?:"|\')'
    r'(https?://[a-zA-Z0-9._\-]+(?::\d+)?(?:/[^\s"\'<>]*)?)'
    r'(?:"|\')'
)

_RE_AJAX_OBJ = re.compile(
    r'\$\.ajax\s*\(\s*\{(.*?)\}',
    re.DOTALL,
)

_RE_UUID = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE,
)

_RE_BARE_OBJECT = re.compile(r',\s*\{(.*?)\}', re.DOTALL)

_RE_SOURCE_MAP = re.compile(r'//#\s*sourceMappingURL\s*=\s*(.+)$', re.MULTILINE)

_SOURCE_ALIASES = {'$': 'jquery', 'jQuery': 'jquery'}
_BLACKLIST = {'log', 'error', 'warn', 'info', 'debug', 'trace', 'dir', 'write', 'writeln'}
_HTTP_VERBS = {'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace', 'connect'}
_VERB_MAP = {
    'get': 'GET', 'post': 'POST', 'put': 'PUT',
    'delete': 'DELETE', 'patch': 'PATCH',
    'head': 'HEAD', 'options': 'OPTIONS',
}


def _normalize_path(path: str) -> str:
    path = _RE_UUID.sub('{id}', path)
    path = re.sub(r'(?<=/)\d+(?=/|$)', '{id}', path)
    return path


def _call_end(content: str, start: int, limit: int = 1000) -> int:
    depth = 0
    in_str = False
    sc = None
    end = min(start + limit, len(content))
    for i in range(start, end):
        c = content[i]
        if in_str:
            if c == sc and (i == start or content[i - 1] != '\\'):
                in_str = False
            continue
        if c in '"\'':
            in_str = True
            sc = c
        elif c == '(':
            depth += 1
        elif c == ')':
            if depth == 0:
                return i
            depth -= 1
    return end


def _extract_params_from_block(block: str) -> list:
    names = []
    for part in re.split(r'[,:]', block):
        part = part.strip()
        if part and re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', part):
            names.append(part)
    return names


class JSAnalyzer:

    def __init__(self, timeout: int = 15, headers: Optional[dict] = None):
        self.timeout = timeout
        self.headers = headers or {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0.0.0"
            ),
            "Accept": "*/*",
        }

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(self, js_urls: list[str]) -> list[dict]:
        results = []
        for url in js_urls:
            content = self._download(url)
            if content:
                results.extend(self.extract_from_content(content, url))
        return results

    def extract_from_content(self, content: str, source_url: str = "") -> list[dict]:
        seen: set = set()
        results: list[dict] = []

        results.extend(self._scan_func_calls(content, source_url, seen))
        results.extend(self._scan_jquery_ajax(content, source_url, seen))
        results.extend(self._scan_obj_urls(content, source_url, seen))
        results.extend(self._scan_path_literals(content, source_url, seen))
        results.extend(self._scan_full_urls(content, source_url, seen))
        results.extend(self._scan_source_map(content, source_url, seen))

        return results

    # ── Download ────────────────────────────────────────────────────────────

    def _download(self, url: str) -> Optional[str]:
        import requests
        try:
            resp = requests.get(
                url, headers=self.headers, timeout=self.timeout, verify=False
            )
            resp.raise_for_status()
            return resp.text
        except Exception:
            logger.debug("Skipped %s — download failed", url)
            return None

    # ── Scan phases ─────────────────────────────────────────────────────────

    def _scan_func_calls(
        self, content: str, source_url: str, seen: set
    ) -> list[dict]:
        results = []
        for m in _RE_FUNC_CALL.finditer(content):
            chain = m.group(1)
            path = m.group(2) or m.group(3)
            if not path.startswith("/") and not path.startswith("http"):
                continue

            parts = chain.split(".")
            fn_name = parts[-1].lower()

            if fn_name in _BLACKLIST:
                continue

            resolved_source, resolved_method = self._resolve_source_method(parts)

            tail = content[m.end():_call_end(content, m.end())]

            # If no method yet, look in trailing object literal
            if not resolved_method:
                mm = _RE_OBJ_METHOD.search(tail)
                if mm:
                    resolved_method = mm.group(1) or mm.group(2)

            resolved_method = resolved_method or "GET"

            params = []
            pm = _RE_PARAMS_BLOCK.search(tail)
            if pm:
                params = _extract_params_from_block(pm.group(1))
            else:
                bm = _RE_BARE_OBJECT.search(tail)
                if bm and ':' not in bm.group(1):
                    params = _extract_params_from_block(bm.group(1))

            entry = self._make_entry(
                path, resolved_source, resolved_method, params, source_url, seen
            )
            if entry:
                results.append(entry)

        return results

    def _scan_jquery_ajax(
        self, content: str, source_url: str, seen: set
    ) -> list[dict]:
        results = []
        for m in _RE_AJAX_OBJ.finditer(content):
            inner = m.group(1)
            path = None
            for um in _RE_OBJ_URL.finditer(inner):
                path = um.group(1) or um.group(2)
            if not path:
                continue
            mm = _RE_OBJ_METHOD.search(inner)
            method = mm.group(1) or mm.group(2) if mm else "GET"
            pm = _RE_PARAMS_BLOCK.search(inner)
            params = _extract_params_from_block(pm.group(1)) if pm else []
            entry = self._make_entry(path, "jquery", method, params, source_url, seen)
            if entry:
                results.append(entry)
        return results

    def _scan_obj_urls(
        self, content: str, source_url: str, seen: set
    ) -> list[dict]:
        results = []
        for m in _RE_OBJ_URL.finditer(content):
            path = m.group(1) or m.group(2)
            if not path:
                continue
            snippet = content[max(0, m.start() - 100):_call_end(content, m.end())]
            mm = _RE_OBJ_METHOD.search(snippet)
            method = mm.group(1) or mm.group(2) if mm else "GET"
            pm = _RE_PARAMS_BLOCK.search(snippet)
            params = _extract_params_from_block(pm.group(1)) if pm else []
            entry = self._make_entry(path, "ajax", method, params, source_url, seen)
            if entry:
                results.append(entry)
        return results

    def _scan_path_literals(
        self, content: str, source_url: str, seen: set
    ) -> list[dict]:
        results = []
        for m in _RE_PATH_LITERAL.finditer(content):
            path = m.group(1)
            entry = self._make_entry(path, "literal", "GET", [], source_url, seen)
            if entry:
                results.append(entry)
        return results

    def _scan_full_urls(
        self, content: str, source_url: str, seen: set
    ) -> list[dict]:
        results = []
        for m in _RE_FULL_URL.finditer(content):
            url = m.group(1)
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or "/"
            base = f"{parsed.scheme}://{parsed.netloc}"
            entry = self._make_entry(path, "url", "GET", [], source_url, seen)
            if entry:
                entry["base_url"] = base
                results.append(entry)
        return results

    def _scan_source_map(
        self, content: str, source_url: str, seen: set
    ) -> list[dict]:
        import requests
        results = []
        for m in _RE_SOURCE_MAP.finditer(content):
            map_path = m.group(1).strip()
            from urllib.parse import urljoin
            map_url = urljoin(source_url, map_path) if source_url else map_path
            try:
                resp = requests.get(
                    map_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,
                )
                if resp.status_code != 200:
                    continue
                mappings = resp.json()
            except Exception:
                continue
            if not isinstance(mappings, dict):
                continue
            for src in mappings.get("sources", []):
                if "node_modules" in src:
                    continue
                results.extend(self.extract_from_content(src, map_url))
            for src_content in mappings.get("sourcesContent", []):
                if src_content:
                    results.extend(self.extract_from_content(src_content, map_url))
        return results

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _resolve_source_method(self, parts: list[str]) -> tuple:
        raw = parts[0]
        source = _SOURCE_ALIASES.get(raw, raw.lower())
        method = None

        if len(parts) > 1:
            last = parts[-1].lower()
            if last in _HTTP_VERBS:
                method = _VERB_MAP.get(last, last.upper())
                suffix_source = ".".join(parts[:-1])
                source = _SOURCE_ALIASES.get(suffix_source, suffix_source.lower())
            else:
                source = _SOURCE_ALIASES.get(source, source.lower())

        return source, method

    def _make_entry(
        self,
        path: str,
        source: str,
        method: str,
        params: list,
        source_url: str,
        seen: set,
    ) -> Optional[dict]:
        path = path.strip().rstrip("/")
        if not path or not path.startswith("/"):
            return None

        path = _normalize_path(path)
        key = (path, method)
        if key in seen:
            return None
        seen.add(key)

        entry: dict = {
            "path": path,
            "source": source,
            "method": method.upper(),
            "params": params,
        }
        if source_url:
            entry["source_url"] = source_url
        return entry


# ── Standalone ───────────────────────────────────────────────────────────────

def main():
    import sys
    urls = sys.argv[1:] if len(sys.argv) > 1 else []
    if not urls:
        line = sys.stdin.read().strip()
        if line:
            urls = [line]
    if not urls:
        print("Uso: python -m src.discovery.services.js_analyzer <url1> <url2> ...")
        print("     echo <url> | python -m src.discovery.services.js_analyzer")
        return
    analyzer = JSAnalyzer()
    results = analyzer.analyze(urls)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
