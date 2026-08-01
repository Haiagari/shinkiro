"""
Local runtime API helpers for PromptWall.

Kept FastAPI shell after the v9 recon stack deletion (guardrail-pivot
slice 1). v9 recon endpoints were removed with their runtime payload
modules; the proxy surface lands in slice 2.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI


app = FastAPI(title="PromptWall", version="9.0.1")


@app.get("/")
def root() -> Dict[str, Any]:
    return {"name": "PromptWall", "version": app.version}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


def start_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")


__all__ = ["app", "start_api"]
