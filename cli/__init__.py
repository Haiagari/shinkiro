# PromptWall CLI Package
"""CLI entry point for PromptWall reconnaissance platform."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("promptwall")
except PackageNotFoundError:
    __version__ = "0.1.0"  # Fallback for non-installed runs