from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.discovery.crawler import run_crawler


def test_run_crawler_creates_downloaded_js_directory(tmp_path):
    args = SimpleNamespace(threads=1, timeout=1)
    js_url = "https://api.example.com/app.js"

    def fake_read_lines(path: Path):
        if path.name == "wayback.txt":
            return [js_url]
        return []

    with (
        patch("src.discovery.crawler.check_tools") as mock_check_tools,
        patch("src.discovery.crawler.run_cmd") as mock_run_cmd,
        patch("src.discovery.crawler.read_lines", side_effect=fake_read_lines),
        patch("src.discovery.crawler.http_client.get") as mock_get,
    ):
        mock_check_tools.return_value = {
            "waybackurls": True,
            "gau": False,
            "katana": False,
            "hakrawler": False,
            "ffuf": False,
        }
        mock_run_cmd.return_value = ""
        mock_get.return_value = SimpleNamespace(status_code=200, content=b"console.log('ok');")

        result = run_crawler(["example.com"], Path(tmp_path), args)

    assert result["downloaded_js"]
    assert (Path(tmp_path) / "downloaded_js").exists()
