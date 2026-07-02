"""
PromptWall OPSEC Module
Maneja rate limiting, identidad, jitter, WAF y kill switch.
"""

from .rate_limiter import RateLimiter, rate_limiter
from .waf_detector import WAFDetector, waf_detector
from .identity_rotation import IdentityRotation, identity_rotation, recon_identity_rotation
from .jitter import Jitter, RateGate, default_jitter, aggressive_jitter, stealth_jitter
from .kill_switch import KillSwitch, kill_switch, check_kill, wait_for_kill

__all__ = [
    # Rate Limiter
    'RateLimiter',
    'rate_limiter',
    # WAF Detector
    'WAFDetector',
    'waf_detector',
    # Identity Rotation
    'IdentityRotation',
    'identity_rotation',
    'recon_identity_rotation',
    # Jitter
    'Jitter',
    'RateGate',
    'default_jitter',
    'aggressive_jitter',
    'stealth_jitter',
    # Kill Switch
    'KillSwitch',
    'kill_switch',
    'check_kill',
    'wait_for_kill',
]