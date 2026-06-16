"""
EnvelopeBuilder - Construcción del sobre de salida estandarizado.
"""

from typing import Any, Dict

from src.core.contracts import (
    CONTRACT_VERSION,
    MODE_ENVELOPE_FIELDS,
    missing_fields,
    validate_required_fields,
)


class EnvelopeBuilder:
    """Builds and validates the standardized output envelope for all modes."""

    VALID_FIELDS: set = set(MODE_ENVELOPE_FIELDS)

    @staticmethod
    def build(
        status: str,
        session_id: str,
        target: str,
        mode: str,
        contract_version: str = CONTRACT_VERSION,
        result: dict | None = None,
        observability: dict | None = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Construye el envelope de salida estandarizado."""
        envelope: Dict[str, Any] = {
            "status": status,
            "session_id": session_id,
            "target": target,
            "mode": mode,
            "contract_version": contract_version,
            "result": result or {},
            "observability": observability or {},
        }
        envelope.update(kwargs)
        validate_required_fields(envelope, MODE_ENVELOPE_FIELDS)
        return envelope

    @staticmethod
    def validate(envelope: dict) -> bool:
        """Valida que un envelope tenga todos los campos requeridos."""
        return len(missing_fields(envelope, MODE_ENVELOPE_FIELDS)) == 0
