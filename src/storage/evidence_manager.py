"""
PromptWall Evidence Manager (v8.3.2)
Handles secure storage of artifacts and evidence files on disk.
"""

import os
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, BinaryIO

from src.core.logging import get_logger

logger = get_logger("storage.evidence")

class EvidenceManager:
    """
    Manages the physical storage of evidence files.
    Implements content-addressable storage using SHA-256 hashes.
    """
    
    def __init__(self, base_dir: str = "evidence"):
        self.base_dir = Path(base_dir)
        self._ensure_base_dir()

    def _ensure_base_dir(self):
        if not self.base_dir.exists():
            self.base_dir.mkdir(parents=True, exist_ok=True)
            # Create a .gitignore to avoid committing evidence
            gitignore = self.base_dir / ".gitignore"
            if not gitignore.exists():
                with open(gitignore, "w") as f:
                    f.write("*\n!.gitignore\n")

    def store(self, content: bytes, extension: str = "bin") -> Tuple[str, str]:
        """
        Stores binary content and returns (relative_path, sha256_hash).
        """
        # Calculate hash
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        # Determine path: evidence/YYYY/MM/DD/hash.ext
        now = datetime.now()
        rel_dir = Path(str(now.year)) / f"{now.month:02d}" / f"{now.day:02d}"
        abs_dir = self.base_dir / rel_dir
        abs_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"{sha256_hash}.{extension.strip('.')}"
        rel_path = rel_dir / filename
        abs_path = self.base_dir / rel_path
        
        # Store if not already exists (deduplication)
        if not abs_path.exists():
            with open(abs_path, "wb") as f:
                f.write(content)
            logger.debug(f"Stored new evidence file: {rel_path}")
        else:
            logger.debug(f"Evidence file already exists (dedup): {rel_path}")
            
        return str(rel_path), sha256_hash

    def get_absolute_path(self, relative_path: str) -> Path:
        """Returns the absolute path for a stored evidence."""
        return self.base_dir / relative_path

    def read(self, relative_path: str) -> Optional[bytes]:
        """Reads content from storage."""
        abs_path = self.get_absolute_path(relative_path)
        if abs_path.exists():
            return abs_path.read_bytes()
        return None

# Global Instance
evidence_manager = EvidenceManager()
