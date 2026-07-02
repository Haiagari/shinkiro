#!/usr/bin/env python3
"""
Stable root entrypoint for PromptWall.

This wrapper keeps the runtime contract explicit:
- `python ozy.py`
- `python -m cli`
- `./ozy`
all dispatch to the same CLI implementation.
"""

from cli.ozy import main


if __name__ == "__main__":
    raise SystemExit(main())
