import json
import hashlib
from typing import Any
from src.domain.models import Finding, Evidence
from src.utils.crypto import EvidenceSigner

class EvidenceService:
    """
    Domain service to handle the creation and signing of evidence.
    Ensures every finding is backed by irrefutable proof.
    """

    def __init__(self, signer: EvidenceSigner):
        """
        Inject the signer. We don't care about key paths or infra here.
        """
        self.signer = signer

    def create_evidence(self, finding: Finding, content: Any, source: str = "PromptWall") -> Evidence:
        """
        Generates signed evidence for a specific finding.
        1. Normalizes content to JSON.
        2. Calculates SHA256 hash.
        3. Signs the data using the injected signer.
        4. Returns a domain Evidence object.
        """
        # Normalize content to JSON string for hashing and signing
        # We ensure it's a stable representation
        normalized_content = json.dumps(content, sort_keys=True)
        
        # Calculate SHA256 Hash
        content_bytes = normalized_content.encode("utf-8")
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        # Sign the data
        # The signer expects a dict or data to canonicalize and sign.
        # To make it irrefutable, we sign the hash + finding context.
        signing_payload = {
            "finding_title": finding.title,
            "content_hash": content_hash,
            "asset_id": finding.asset_id
        }
        
        signature = self.signer.sign_data(signing_payload)

        return Evidence(
            content=normalized_content,
            source=source,
            content_hash=content_hash,
            signature=signature,
            metadata={
                "finding_title": finding.title,
                "asset_id": finding.asset_id
            }
        )
