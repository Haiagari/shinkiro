"""
Evidence Capture Module.
Captures request/response evidence for findings and generates screenshots.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict


@dataclass
class CapturedRequest:
    timestamp: str
    method: str
    url: str
    status_code: int
    response_headers: dict = field(default_factory=dict)
    response_body_preview: str = ""
    curl_command: str = ""
    screenshot_path: Optional[str] = None
    notes: str = ""


class EvidenceCollector:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.evidence_dir = output_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.collected: list[CapturedRequest] = []

    def capture_http(self, method: str, url: str, headers: Optional[dict] = None,
                     body: Optional[str] = None, note: str = "") -> CapturedRequest:
        import urllib.request
        req = urllib.request.Request(url, method=method,
            headers=headers or {"User-Agent": "Mozilla/5.0"},
            data=body.encode() if body else None)
        try:
            t0 = time.time()
            resp = urllib.request.urlopen(req, timeout=10)
            elapsed = time.time() - t0
            resp_body = resp.read().decode("utf-8", errors="ignore")[:2000]
            curl = f"curl -X {method} '{url}'"
            if headers:
                for k, v in headers.items():
                    curl += f" -H '{k}: {v}'"
            captured = CapturedRequest(
                timestamp=datetime.utcnow().isoformat(),
                method=method,
                url=url,
                status_code=resp.status,
                response_headers=dict(resp.headers),
                response_body_preview=resp_body[:500],
                curl_command=curl,
                notes=note,
            )
        except urllib.error.HTTPError as e:
            captured = CapturedRequest(
                timestamp=datetime.utcnow().isoformat(),
                method=method,
                url=url,
                status_code=e.code,
                response_headers=dict(e.headers),
                response_body_preview=e.read().decode("utf-8", errors="ignore")[:500],
                curl_command=f"curl -X {method} '{url}'",
                notes=f"{note} (HTTP {e.code})",
            )
        except Exception as e:
            captured = CapturedRequest(
                timestamp=datetime.utcnow().isoformat(),
                method=method,
                url=url,
                status_code=0,
                notes=f"{note} ERROR: {e}",
                curl_command=f"curl -X {method} '{url}'",
            )

        self.collected.append(captured)
        self._save_evidence(captured)
        return captured

    def _save_evidence(self, captured: CapturedRequest):
        safe_name = captured.url.replace("https://", "").replace("http://", "").replace("/", "_")[:60]
        path = self.evidence_dir / f"{safe_name}.json"
        path.write_text(json.dumps(asdict(captured), indent=2))

    def export_markdown(self) -> str:
        lines = []
        for c in self.collected:
            lines.append(f"### {c.method} {c.url}")
            lines.append(f"**Status:** {c.status_code}")
            lines.append(f"**Timestamp:** {c.timestamp}")
            if c.notes:
                lines.append(f"**Note:** {c.notes}")
            lines.append("")
            lines.append("```bash")
            lines.append(c.curl_command)
            lines.append("```")
            lines.append("")
            lines.append("**Response (preview):**")
            lines.append("```")
            lines.append(c.response_body_preview[:300])
            lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")
        return "\n".join(lines)

    def export_json(self) -> list:
        return [asdict(c) for c in self.collected]
