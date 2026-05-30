"""Root conftest for pytest isolation."""
import sys
from pathlib import Path

# Prevent tools/go/pkg from polluting imports
_tools_path = str(Path(__file__).parent / "tools")
sys.path = [p for p in sys.path if not p.startswith(_tools_path)]

collect_ignore_glob = ["tools/**", "runtime/**"]
