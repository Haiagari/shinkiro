"""
PromptWall Modes Module
Los 6 modos operativos del framework.
"""

from .hunt import HuntMode, run_hunt
from .continuous import ContinuousMode, run_continuous
from .campaign import CampaignMode, run_campaign
from .research import ResearchMode, run_research
from .forensic import ForensicMode, run_forensic
from .servicio import ServiceMode, run_servicio

__all__ = [
    # Hunt
    'HuntMode',
    'run_hunt',
    # Continuous
    'ContinuousMode',
    'run_continuous',
    # Campaign
    'CampaignMode',
    'run_campaign',
    # Research
    'ResearchMode',
    'run_research',
    # Forensic
    'ForensicMode',
    'run_forensic',
    # Servicio
    'ServiceMode',
    'run_servicio',
]