"""
Validation policy for OzyRecon.

This module makes the probing contract explicit:
- safe: low-risk metadata or exposure confirmation
- gate_required: approved-but-sensitive checks that should remain human-visible
- blocked: validations that should not run in the default production flow
"""

from dataclasses import dataclass
from typing import Dict, Any
from urllib.parse import urlparse
import ipaddress


@dataclass(frozen=True)
class ValidationPolicyDecision:
    action: str
    reason: str

    @property
    def is_safe(self) -> bool:
        return self.action == "safe"

    @property
    def requires_gate(self) -> bool:
        return self.action == "gate_required"

    @property
    def is_blocked(self) -> bool:
        return self.action == "blocked"


class ValidationPolicy:
    """
    Classifies hypotheses before validation.
    """

    SAFE_TYPES = {
        "EXPOSED_VERSION",
        "SENSITIVE_FILE",
        "HTTP",
        "INFRA",
    }

    GATE_REQUIRED_TYPES = {
        "DEFAULT_AUTH",
        "AUTOMATION_PANEL",
        "EXPOSED_DATABASE",
        "EXPOSED_SECRET",
        "AUTH",
    }

    BLOCKED_TYPES = {
        "RCE",
        "COMMAND_INJECTION",
        "DESTRUCTIVE",
        "EXPLOIT",
    }

    def classify(self, hypothesis: Dict[str, Any]) -> ValidationPolicyDecision:
        h_type = str(hypothesis.get("type", "")).upper().strip()
        url = str(hypothesis.get("url", "")).strip()

        if not h_type:
            return ValidationPolicyDecision("blocked", "missing hypothesis type")

        if not url:
            return ValidationPolicyDecision("blocked", "missing target url")

        scope_decision = self.scope_decision(url)
        if scope_decision.is_blocked:
            return scope_decision

        if h_type in self.BLOCKED_TYPES:
            return ValidationPolicyDecision("blocked", f"{h_type} is not allowed in the default flow")

        if h_type in self.SAFE_TYPES:
            return ValidationPolicyDecision("safe", f"{h_type} is safe to validate automatically")

        if h_type in self.GATE_REQUIRED_TYPES:
            return ValidationPolicyDecision("gate_required", f"{h_type} should remain explicitly gated")

        if h_type.endswith("_PANEL") or "AUTH" in h_type or "CONFIG" in h_type:
            return ValidationPolicyDecision("gate_required", f"{h_type} is a sensitive validation path")

        return ValidationPolicyDecision("safe", f"{h_type} can run under the default controlled probing flow")

    def _normalize_url(self, raw_url: str) -> str:
        value = raw_url.strip()
        if "://" not in value:
            value = f"https://{value.lstrip('/')}"
        return value

    def scope_decision(self, raw_url: str) -> ValidationPolicyDecision:
        normalized = self._normalize_url(raw_url)
        parsed = urlparse(normalized)
        host = parsed.hostname

        if parsed.scheme not in {"http", "https"}:
            return ValidationPolicyDecision("blocked", f"unsupported URL scheme: {parsed.scheme}")

        if not host:
            return ValidationPolicyDecision("blocked", "missing hostname in target url")

        if host in {"localhost"} or host.endswith(".local"):
            return ValidationPolicyDecision("blocked", f"{host} is not allowed in the default scope")

        try:
            ip = ipaddress.ip_address(host)
            if any([ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_reserved, ip.is_multicast]):
                return ValidationPolicyDecision("blocked", f"{host} is not allowed in the default scope")
        except ValueError:
            pass

        return ValidationPolicyDecision("safe", f"{host} is within the default controlled scope")


validation_policy = ValidationPolicy()
