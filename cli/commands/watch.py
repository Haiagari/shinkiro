"""
CLI Command: watch - OzyRecon v8.3
Real-time certificate transparency log monitoring for new assets.
"""

import click
import time
import requests
import logging
import difflib
from datetime import datetime
from rich.live import Live
from rich.table import Table
from src.core.logging import console
from src.notifications.notifier import notifier
from src.core.runtime_paths import get_runtime_root

logger = logging.getLogger("commands.watch")

def fetch_crt_sh(domain: str):
    """Fetches subdomains from crt.sh API."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=20)
        if response.ok:
            return response.json()
    except:
        pass
    return []

def get_http_content(url: str) -> str:
    """Intenta obtener el contenido de una URL para comparar."""
    try:
        # Usamos un timeout corto para no trabar el loop
        res = requests.get(f"http://{url}", timeout=5, verify=False)
        return res.text
    except:
        return ""

def store_response(name: str, content: str):
    """Guarda el contenido de la respuesta en disco."""
    path = get_runtime_root() / "watch_history" / f"{name}.body"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def get_stored_response(name: str) -> str:
    """Recupera el contenido guardado previamente."""
    path = get_runtime_root() / "watch_history" / f"{name}.body"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def show_diff(name: str, old: str, new: str):
    """Muestra el diff entre dos versiones de contenido."""
    diff = difflib.unified_diff(
        old.splitlines(), 
        new.splitlines(), 
        fromfile=f"{name} (Old)", 
        tofile=f"{name} (New)",
        lineterm=""
    )
    diff_text = "\n".join(list(diff)[:10]) # Solo mostramos las primeras 10 líneas de diff
    if diff_text:
        console.print(f"[bold yellow]⚠️ CONTENT CHANGE DETECTED on {name}:[/bold yellow]")
        console.print(f"[dim]{diff_text}[/dim]")

@click.command(name="watch")
@click.argument("target_domain")
@click.option("--interval", default=60, help="Polling interval in seconds")
def watch(target_domain, interval):
    """Monitor Certificate Transparency logs for new subdomains in real-time."""
    console.print(f"[bold blue]👁️ Sentinel Watcher active for {target_domain}...[/bold blue]")
    console.print(f"[dim]Polling crt.sh every {interval}s. CTRL+C to stop.[/dim]\n")
    
    known_certs = set()
    
    # Initial load
    initial_data = fetch_crt_sh(target_domain)
    for entry in initial_data:
        known_certs.add(entry.get('id'))
    
    console.print(f"[green]Initial state loaded: {len(known_certs)} certificates known.[/green]")

    try:
        while True:
            time.sleep(interval)
            current_data = fetch_crt_sh(target_domain)
            
            new_entries = []
            for entry in current_data:
                cert_id = entry.get('id')
                if cert_id not in known_certs:
                    new_entries.append(entry)
                    known_certs.add(cert_id)
            
            if new_entries:
                for new in new_entries:
                    name = new.get('common_name')
                    issuer = new.get('issuer_name')
                    msg = f"🆕 NEW ASSET DETECTED: {name}"
                    console.print(f"[bold gold1]{msg}[/bold gold1]")
                    console.print(f"   Issuer: {issuer}")
                    
                    # Differential Intelligence: Compare content
                    current_content = get_http_content(name)
                    old_content = get_stored_response(name)
                    
                    if old_content and old_content != current_content:
                        show_diff(name, old_content, current_content)
                    
                    store_response(name, current_content)

                    # Notify via Telegram
                    notifier.send_alert(
                        "Sentinel Watcher: New Asset",
                        f"Target: {target_domain}\nNew Host: {name}\nIssuer: {issuer}",
                        severity="high"
                    )
            else:
                timestamp = datetime.now().strftime("%H:%M:%S")
                console.print(f"[dim][{timestamp}] No new assets found.[/dim]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Watcher stopped. Goodbye![/yellow]")
