"""
Init Command - Initialize OzyRecon environment
Creates necessary directories, config files, and sets up the project.
"""

import os
from pathlib import Path

import click
from cli.shared import console, render_outcome, render_panel


def ensure_dir(path: Path) -> bool:
    """Ensure a directory exists."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def create_gitignore(path: Path, content: str) -> bool:
    """Create a .gitignore file if it doesn't exist."""
    try:
        if not path.exists():
            path.write_text(content + "\n")
        return True
    except Exception:
        return False


def create_example_config(path: Path, name: str, content: str) -> bool:
    """Create an example config file."""
    try:
        example_path = path.with_name(name)
        if not example_path.exists():
            example_path.write_text(content)
        return True
    except Exception:
        return False


@click.command(name="init")
@click.option("--force", is_flag=True, help="Force reinitialize existing directories")
def init(force: bool):
    """
    Initialize OzyRecon environment.
    
    Creates:
    - runs/
    - reports/pruebas/
    - reports/reales/
    - exports/
    - evidence/
    - resources/rules/
    - resources/templates/
    - resources/keys/
    - config/
    - .env.example
    - .gitignore
    """
    render_panel("[bold cyan]OzyRecon Init[/bold cyan] - Environment Setup", border_style="cyan")
    
    base = Path("/home/sam/Proyectos/OzyRecon")
    dirs_created = 0
    files_created = 0
    
    # Directories to create
    directories = [
        ("runs", base / "runs"),
        ("reports/pruebas", base / "reports" / "pruebas"),
        ("reports/reales", base / "reports" / "reales"),
        ("exports", base / "exports"),
        ("exports/siem", base / "exports" / "siem"),
        ("evidence", base / "evidence"),
        ("resources/rules", base / "resources" / "rules"),
        ("resources/templates", base / "resources" / "templates"),
        ("resources/keys", base / "resources" / "keys"),
    ]
    
    console.print("\n[bold]Creating directories...[/bold]")
    
    for name, path in directories:
        if force or not path.exists():
            if ensure_dir(path):
                console.print(f"  ✓ {name}: {path}")
                dirs_created += 1
            else:
                console.print(f"  ✗ {name}: Failed to create")
        else:
            console.print(f"  → {name}: Already exists")
    
    # Create .gitignore
    console.print("\n[bold]Creating .gitignore...[/bold]")
    gitignore_content = """
# Evidence and artifacts
runs/
reports/reales/
exports/
evidence/

# Python
__pycache__/
*.py[cod]
*$py.class

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Keys and secrets
config/*.json
!config/*.example.json
.env

# Logs
*.log

# Test artifacts
.pytest_cache/
.coverage
htmlcov/
"""
    gitignore_path = base / ".gitignore"
    if create_gitignore(gitignore_path, gitignore_content):
        console.print(f"  ✓ .gitignore")
        files_created += 1
    
    # Create example .env
    console.print("\n[bold]Creating .env.example...[/bold]")
    env_example = """# OzyRecon Environment Configuration
# Copy this file to .env and fill in your values

# API Keys (optional)
# GEMINI_API_KEY=your_api_key_here
# SHODAN_API_KEY=your_api_key_here
# VIRUSTOTAL_API_KEY=your_api_key_here

# Rate limiting (requests per minute)
RATE_LIMIT=50

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO

# Report format (html, pdf, both)
REPORT_FORMAT=html
"""
    env_path = base / ".env.example"
    if create_gitignore(env_path, env_example):
        console.print(f"  ✓ .env.example")
        files_created += 1
    
    # Create example scope file
    console.print("\n[bold]Creating scope.yaml.example...[/bold]")
    scope_example = """# OzyRecon Scope Configuration
# Copy this file to config/scope.yaml and customize

target: example.com

allowed_domains:
  - example.com
  - "*.example.com"

forbidden_patterns:
  - test
  - internal
  - staging
  - dev

profiles_allowed:
  - passive
  - safe-active

authorization:
  type: academic  # academic, client, internal
  reference: "Project identifier or client name"
  date: "2026-01-01"
  authorized_by: "Name of person or entity"
"""
    scope_path = base / "config" / "scope.yaml.example"
    if create_gitignore(scope_path, scope_example):
        console.print(f"  ✓ scope.yaml.example")
        files_created += 1
    
    render_outcome("Initialization complete!")
    render_panel(
        "\n".join([
            "[bold]Next steps:[/bold]",
            "  1. Copy .env.example to .env and add your API keys (optional)",
            "  2. Copy config/scope.yaml.example to config/scope.yaml",
            "  3. Run: python ozy.py doctor",
            "  4. Run: python ozy.py flow <target> --profile passive",
        ]),
        border_style="cyan",
    )


__all__ = ["init"]
