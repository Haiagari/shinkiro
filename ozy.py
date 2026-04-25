#!/usr/bin/env python3
"""
OzyRecon — Unified Entry Point
Usage:
  ./ozy.py          # Launches TUI (default)
  ./ozy.py --cli    # Launches CLI mode
"""
import sys
import argparse
from cli.main import main as run_cli
from cli.tui import run_tui

def run():
    parser = argparse.ArgumentParser(description="OzyRecon Unified Interface")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode instead of TUI")
    args, unknown = parser.parse_known_args()

    if args.cli:
        # Pass unknown args to the original CLI main
        sys.argv = [sys.argv[0]] + unknown
        sys.exit(run_cli())
    else:
        # Default to TUI
        # You might want to fetch these from config in the future
        run_tui(username="sam", api_base="http://localhost:5000", api_ok=True)

if __name__ == "__main__":
    run()
