"""
CVSS v3.1 Calculator for security findings.
Generates vector strings and scores from finding attributes.
"""

from math import ceil
from dataclasses import dataclass


@dataclass
class CVSSVector:
    AV: str = "N"  # Attack Vector: N(etwork) A(djacent) L(ocal) P(hysical)
    AC: str = "L"  # Attack Complexity: L(ow) H(igh)
    PR: str = "N"  # Privileges Required: N(one) L(ow) H(igh)
    UI: str = "N"  # User Interaction: N(one) R(equired)
    S: str = "U"   # Scope: U(nchanged) C(hanged)
    C: str = "H"   # Confidentiality: H(igh) L(ow) N(one)
    I: str = "H"   # Integrity: H(igh) L(ow) N(one)
    A: str = "H"   # Availability: H(igh) L(ow) N(one)
    E: str = "X"   # Exploit Code Maturity: X(not defined) H(igh) F(unctional) P(roof-of-concept) U(nproven)

    def vector(self) -> str:
        return f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}/E:{self.E}"

    def score(self) -> float:
        return _compute_base_score(self)


_ISC_MAP = {"H": 0.56, "L": 0.22, "N": 0.0}
_ESC_MAP = {"H": 0.44, "L": 0.22, "N": 0.0}
_AC_MAP = {"L": 0.77, "H": 0.44}
_PR_MAP_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_PR_MAP_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_UI_MAP = {"N": 0.85, "R": 0.62}
_AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}


def _roundup(val: float) -> float:
    return ceil(val * 10) / 10.0


def _compute_impact(v: CVSSVector) -> float:
    """Compute Impact sub-score per CVSS v3.1 spec."""
    isc = 1.0 - ((1.0 - _ISC_MAP[v.C]) * (1.0 - _ISC_MAP[v.I]) * (1.0 - _ISC_MAP[v.A]))
    if v.S == "C":
        return 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    return 6.42 * isc


def _compute_base_score(v: CVSSVector) -> float:
    impact = _compute_impact(v)
    if impact <= 0:
        return 0.0

    if v.S == "C":
        pr = _PR_MAP_CHANGED[v.PR]
    else:
        pr = _PR_MAP_UNCHANGED[v.PR]

    exploitability = 8.22 * _AV_MAP[v.AV] * _AC_MAP[v.AC] * pr * _UI_MAP[v.UI]

    if v.S == "C":
        base = min(1.08 * (exploitability + impact), 10.0)
    else:
        base = min(exploitability + impact, 10.0)

    return _roundup(base)


def severity_from_score(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "NONE"


FINDING_TEMPLATES = {
    "wp_user_enum": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="C",
        C="L", I="L", A="N", E="F",
    ),
    "debug_panel_exposed": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="C",
        C="H", I="H", A="H", E="P",
    ),
    "api_info_leak": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="U",
        C="L", I="N", A="N", E="P",
    ),
    "admin_panel_exposed": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="U",
        C="H", I="H", A="L", E="P",
    ),
    "wordpress_xmlrpc": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="U",
        C="L", I="L", A="N", E="F",
    ),
    "server_error_5xx": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="U",
        C="L", I="N", A="L", E="U",
    ),
    "cms_outdated": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="C",
        C="H", I="H", A="H", E="P",
    ),
    "default_creds": CVSSVector(
        AV="N", AC="L", PR="N", UI="N", S="C",
        C="H", I="H", A="H", E="F",
    ),
}


def score_finding(finding_type: str, **overrides) -> tuple[str, float, str]:
    if finding_type not in FINDING_TEMPLATES:
        raise ValueError(f"Unknown finding type: {finding_type}")
    vec = FINDING_TEMPLATES[finding_type]
    for k, v in overrides.items():
        if hasattr(vec, k.upper()):
            setattr(vec, k.upper(), v)
    s = vec.score()
    sev = severity_from_score(s)
    return vec.vector(), s, sev
