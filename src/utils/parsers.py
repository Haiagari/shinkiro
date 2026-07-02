"""
PromptWall Robust Parsers (v9.0.1)
Centralized parsing for tool outputs to prevent crashes and ensure data quality.
"""

import re
import json
import logging
from typing import Any, List, Dict, Optional

logger = logging.getLogger("utils.parsers")

def parse_duration_ms(time_str: Any) -> int:
    """
    Robustly parses time strings like '2.3s', '250ms', or raw floats into integer milliseconds.
    """
    if not time_str:
        return 0
    
    raw = str(time_str).lower().strip()
    try:
        # Handle 's' suffix
        if raw.endswith('s') and not raw.endswith('ms'):
            return int(float(raw.replace('s', '')) * 1000)
        # Handle 'ms' suffix
        if raw.endswith('ms'):
            return int(float(raw.replace('ms', '')))
        # Handle raw float/int
        return int(float(raw))
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse duration '{time_str}': {e}")
        return 0

def clean_json_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Attempts to parse a single line of JSON, handling common tool output quirks.
    """
    if not line or not line.strip():
        return None
    
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        # Try to find JSON block in line if it has extra text
        match = re.search(r'(\{.*\})', line)
        if match:
            try:
                return json.loads(match.group(1))
            except: pass
    return None

def normalize_ip(ip_data: Any) -> Optional[str]:
    """Ensures IP data is a valid string or extracted from a list."""
    if not ip_data:
        return None
    if isinstance(ip_data, list) and len(ip_data) > 0:
        return str(ip_data[0])
    return str(ip_data)
