"""
Advanced Key Store - OzyRecon v8.1
Handles API Key hashing, storage and validation.
Never stores keys in plaintext.
"""

import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

from src.core.bootstrap import ensure_api_key_registry

logger = logging.getLogger("auth.key_store")

class KeyStore:
    def __init__(self, storage_path: str = "config/api_keys.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        ensure_api_key_registry(self.storage_path)
        if not self.storage_path.exists():
            self._save_keys([])

    def _hash_key(self, api_key: str) -> str:
        """Computes SHA-256 hash with prefix."""
        h = hashlib.sha256(api_key.encode()).hexdigest()
        return f"sha256:{h}"

    def _load_keys(self) -> List[Dict]:
        try:
            with open(self.storage_path, "r") as f:
                return json.load(f).get("keys", [])
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            return []

    def _save_keys(self, keys: List[Dict]):
        with open(self.storage_path, "w") as f:
            json.dump({"keys": keys, "updated_at": datetime.now().isoformat()}, f, indent=2)

    def create_key(self, name: str, scopes: List[str], rate_limit: int = 60, prefix: str = "ozy_live_") -> Tuple[str, str]:
        """Creates a new key, saves its hash, and returns the plaintext key once."""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        random_part = ''.join(secrets.choice(alphabet) for _ in range(32))
        api_key = f"{prefix}{random_part}"
        key_hash = self._hash_key(api_key)
        
        new_key_entry = {
            "name": name,
            "key_hash": key_hash,
            "scopes": scopes,
            "rate_limit_per_min": rate_limit,
            "enabled": True,
            "created_at": datetime.now().isoformat(),
            "last_used_at": None
        }
        
        keys = self._load_keys()
        # Prevent duplicate names
        keys = [k for k in keys if k["name"] != name]
        keys.append(new_key_entry)
        self._save_keys(keys)
        
        return name, api_key

    def verify_key(self, api_key: str) -> Optional[Dict]:
        """Verifies a plaintext key against stored hashes."""
        target_hash = self._hash_key(api_key)
        keys = self._load_keys()
        for k in keys:
            if k["key_hash"] == target_hash and k["enabled"]:
                # Update last used
                k["last_used_at"] = datetime.now().isoformat()
                self._save_keys(keys)
                return k
        return None

    def revoke_key(self, name: str) -> bool:
        keys = self._load_keys()
        updated_keys = [k for k in keys if k["name"] != name]
        if len(updated_keys) < len(keys):
            self._save_keys(updated_keys)
            return True
        return False

    def list_keys(self) -> List[Dict]:
        # Return keys without hashes for safety
        keys = self._load_keys()
        for k in keys:
            k.pop("key_hash", None)
        return keys

# Global Instance
key_store = KeyStore()
