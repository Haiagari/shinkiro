"""
Cryptography Utility for Evidence Integrity (OzyRecon v7.5)
Handles digital signing of discovery artifacts to ensure chain of custody.
"""

import json
import logging
import base64
from pathlib import Path
from typing import Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

class EvidenceSigner:
    """
    Signs and verifies JSON evidence using Ed25519.
    """

    def __init__(self, key_path: str = "resources/keys/evidence_key.priv"):
        self.key_path = Path(key_path)
        self.private_key = self._load_or_generate_key()
        self.public_key = self.private_key.public_key()

    def _load_or_generate_key(self) -> ed25519.Ed25519PrivateKey:
        """Loads the private key from disk or generates a new one."""
        if self.key_path.exists():
            try:
                with open(self.key_path, "rb") as f:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
            except Exception as e:
                logger.error(f"Failed to load evidence key: {e}")
        
        # Generate new key
        logger.info("Generating new Ed25519 key for evidence signing.")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = ed25519.Ed25519PrivateKey.generate()
        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes_raw())
        return key

    def sign_data(self, data: Dict) -> str:
        """
        Signs a dictionary and returns a base64 signature.
        Canonicalizes JSON before signing.
        """
        try:
            canonical_json = json.dumps(data, sort_keys=True).encode("utf-8")
            signature = self.private_key.sign(canonical_json)
            return base64.b64encode(signature).decode("utf-8")
        except Exception as e:
            logger.error(f"Error signing evidence: {e}")
            return ""

    def verify_data(self, data: Dict, signature_b64: str) -> bool:
        """Verifies a signature against data."""
        try:
            canonical_json = json.dumps(data, sort_keys=True).encode("utf-8")
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(signature, canonical_json)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    def get_public_key_b64(self) -> str:
        """Returns the public key for verification elsewhere."""
        return base64.b64encode(self.public_key.public_bytes_raw()).decode("utf-8")

# Global Instance
evidence_signer = EvidenceSigner()
