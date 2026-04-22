"""
Visual Utilities - Captura de evidencia visual v5.7
"""

import os
import hashlib
from datetime import datetime
from src.core.logging import get_logger

logger = get_logger('utils.visual')

def capture_screenshot(url: str, hypothesis_id: str) -> str:
    """
    Captura un screenshot de la URL y lo guarda en el directorio de evidencias.
    Retorna el path relativo al archivo.
    """
    evidence_dir = os.path.join("runtime", "evidence", "screenshots")
    os.makedirs(evidence_dir, exist_ok=True)
    
    filename = f"{hypothesis_id}_{hashlib.md5(url.encode()).hexdigest()[:8]}.png"
    filepath = os.path.join(evidence_dir, filename)
    
    logger.info(f"Attempting to capture screenshot for {url} -> {filepath}")
    
    # --- IMPLEMENTACIÓN CON PLAYWRIGHT (PENDIENTE DE INSTALACIÓN) ---
    try:
        # Esto fallará si no está instalado, lo que es capturado por el validador
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=30000)
            page.screenshot(path=filepath)
            browser.close()
            
        logger.info(f"Screenshot saved successfully: {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Playwright screenshot failed: {str(e)}")
        # Placeholder: Si falla, al menos dejamos rastro
        return ""
