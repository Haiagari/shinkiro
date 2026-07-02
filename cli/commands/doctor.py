"""
PromptWall Doctor - Environment Validation Command
Verifies that all dependencies, tools, and configurations are properly set up.
"""

import sys
import shutil
import subprocess
from pathlib import Path

import click
from rich.table import Table

from cli.shared import console, render_outcome, render_panel
from src.core.config import config
from src.storage.database import engine


def check_python():
    """Check Python version."""
    version = sys.version_info
    status = "OK" if version >= (3, 11) else "WARN"
    return {
        "name": "Python",
        "version": f"{version.major}.{version.minor}.{version.micro}",
        "status": status,
        "message": f"Python {version.major}.{version.minor}.{version.micro}" if status == "OK" else "Requires Python 3.11+"
    }


def check_folders():
    """Check required folders."""
    base = Path("/home/sam/Proyectos/PromptWall")
    folders = [
        ("runs", base / "runs"),
        ("resources/rules", base / "resources/rules"),
        ("resources/keys", base / "resources/keys"),
        ("config", base / "config"),
        ("tools/go/bin", base / "tools" / "go" / "bin"),
    ]
    
    results = []
    for name, path in folders:
        exists = path.exists()
        results.append({
            "name": name,
            "version": "OK" if exists else "MISSING",
            "status": "OK" if exists else "FAIL",
            "message": str(path) if exists else f"{name} not found"
        })
    return results


def check_go_binaries():
    """Check Go binary tools."""
    tools = [
        "subfinder",
        "dnsx", 
        "httpx",
        "nuclei",
        "amass",
        "katana",
        "gowitness",
        "nmap",
    ]
    
    results = []
    for tool in tools:
        path = shutil.which(tool)
        # Check local tools first
        if not path:
            local_path = Path(f"/home/sam/Proyectos/PromptWall/tools/go/bin/{tool}")
            if local_path.exists():
                path = str(local_path)
        
        results.append({
            "name": tool,
            "version": path.split("/")[-1] if path else "NOT FOUND",
            "status": "OK" if path else "FAIL",
            "message": path if path else f"{tool} not in PATH or tools/go/bin/"
        })
    return results


def check_python_deps():
    """Check Python dependencies."""
    deps = [
        ("sqlalchemy", "sqlalchemy"),
        ("requests", "requests"),
        ("rich", "rich"),
        ("click", "click"),
        ("curl_cffi", "curl_cffi"),
    ]
    optional_deps = [
        ("weasyprint", "weasyprint", "PDF export (optional)"),
    ]
    
    results = []
    
    # Required dependencies
    for name, import_name in deps:
        try:
            __import__(import_name)
            results.append({
                "name": name,
                "version": "OK",
                "status": "OK",
                "message": "Installed"
            })
        except ImportError:
            results.append({
                "name": name,
                "version": "MISSING",
                "status": "FAIL",
                "message": "Required - install with pip"
            })
    
    # Optional dependencies
    for name, import_name, note in optional_deps:
        try:
            __import__(import_name)
            results.append({
                "name": name,
                "version": "OK",
                "status": "OK",
                "message": "Installed"
            })
        except ImportError:
            results.append({
                "name": name,
                "version": "MISSING",
                "status": "WARN",
                "message": f"Not installed - {note}"
            })
    
    return results


def check_api_keys():
    """Check optional API keys (stub - for future implementation)."""
    return [{"name": "API Keys", "version": "N/A", "status": "OK", "message": "Optional - not validated"}]


def check_database():
    """Check database connection."""
    try:
        from src.storage.database import engine
        conn = engine.connect()
        conn.close()
        return {"name": "Database", "version": "OK", "status": "OK", "message": "SQLite connection successful"}
    except Exception as e:
        return {"name": "Database", "version": "ERROR", "status": "FAIL", "message": str(e)[:50]}


@click.command(name="doctor")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def doctor(json_output):
    """
    Validate PromptWall environment and dependencies.
    
    Runs a comprehensive check of:
    - Python version
    - Required folders
    - Go binaries
    - Python dependencies
    - API keys (optional)
    - Database connection
    """
    render_panel("[bold cyan]PromptWall Doctor[/bold cyan] - Environment Validation", border_style="cyan")
    
    all_results = []
    
    # Python
    all_results.append(("Python", [check_python()]))
    
    # Folders
    all_results.append(("Folders", check_folders()))
    
    # Go binaries
    all_results.append(("Go Tools", check_go_binaries()))
    
    # Python deps
    all_results.append(("Python Deps", check_python_deps()))
    
    # API keys
    all_results.append(("API Keys", check_api_keys()))
    
    # Database
    all_results.append(("Database", [check_database()]))
    
    if json_output:
        import json
        output = {}
        for category, items in all_results:
            output[category] = items
        console.print_json(json.dumps(output, indent=2))
        return
    
    # Display results
    for category, items in all_results:
        table = Table(title=f"[bold]{category}[/bold]", show_header=True, header_style="bold magenta")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Notes", style="white")
        
        for item in items:
            status_color = {
                "OK": "[green]OK[/green]",
                "WARN": "[yellow]WARN[/yellow]",
                "FAIL": "[red]FAIL[/red]",
            }.get(item["status"], item["status"])
            
            table.add_row(
                item["name"],
                status_color,
                item["message"]
            )
        
        console.print(table)
        console.print()
    
    # Summary
    all_items = [item for _, items in all_results for item in items]
    failures = sum(1 for i in all_items if i["status"] == "FAIL")
    warnings = sum(1 for i in all_items if i["status"] == "WARN")
    
    if failures > 0:
        render_outcome(f"Status: FAIL - {failures} critical issue(s)", border_style="red")
    elif warnings > 0:
        render_outcome(f"Status: READY WITH WARNINGS - {warnings} optional component(s) missing", border_style="yellow")
    else:
        render_outcome("Status: READY - All checks passed")


__all__ = ["doctor"]
