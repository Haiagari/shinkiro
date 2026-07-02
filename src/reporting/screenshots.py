"""
Screenshot Capture Module.
Uses gowitness for automated headless screenshots of findings.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional


GOWITNESS_PATH = "/home/sam/Proyectos/PromptWall/tools/go/bin/gowitness"


def capture_screenshot(url: str, output_dir: Path, label: str = "") -> Optional[Path]:
    """Capture a screenshot of a URL using gowitness."""
    if not Path(GOWITNESS_PATH).exists():
        raise RuntimeError(f"gowitness not found at {GOWITNESS_PATH}")

    safe = label.replace(" ", "_") if label else url.replace("https://", "").replace("http://", "").replace("/", "_")
    out_file = output_dir / f"screenshot_{safe}.png"

    cmd = [
        GOWITNESS_PATH, "scan", "single",
        "--url", url,
        "--screenshot-path", str(output_dir),
        "--timeout", "15",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            from urllib.parse import urlparse
            hostname = urlparse(url).netloc
            for ext in [".jpeg", ".jpg", ".png"]:
                gf = output_dir / f"{hostname}{ext}"
                if gf.exists():
                    gf.rename(out_file)
                    return out_file
            for f in output_dir.glob("*.[jp][pn]*"):
                if f.stat().st_size > 1000:
                    f.rename(out_file)
                    return out_file
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def capture_batch(urls: list[str], output_dir: Path) -> list[dict]:
    """Capture screenshots for multiple URLs and return results."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    for url in urls:
        path = capture_screenshot(url, output_dir)
        results.append({
            "url": url,
            "screenshot": str(path) if path else None,
            "status": "captured" if path else "failed",
        })

    manifest = output_dir / "_screenshots.json"
    manifest.write_text(json.dumps(results, indent=2))
    return results
