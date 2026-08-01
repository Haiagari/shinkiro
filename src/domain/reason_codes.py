"""Stable enumerated reason codes for guardrail decisions.

Each code is a stable machine-readable string carried in error bodies
(403/401/429/422/502) and audit entries (see design.md).
"""

from enum import Enum


class ReasonCode(str, Enum):
    """Machine-readable codes returned by the guardrail proxy."""

    POLICY_BLOCK = "policy_block"  # 403, plus rule_id
    JUDGE_BLOCK = "judge_block"  # 403, plus judge reason
    JUDGE_UNAVAILABLE = "judge_unavailable"  # 403, fail-closed
    INJECTION = "injection"  # granular rule/judge reason
    JAILBREAK = "jailbreak"
    PII_EXFILTRATION = "pii_exfiltration"
    INSUFFICIENT_SCOPE = "insufficient_scope"  # 403
    UNAUTHENTICATED = "unauthenticated"  # 401
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"  # 429
    VALIDATION_ERROR = "validation_error"  # 422
    UPSTREAM_FAILURE = "upstream_failure"  # 502
    NOT_FOUND = "not_found"  # 404


__all__ = ["ReasonCode"]
