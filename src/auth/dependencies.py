"""
Auth Dependencies & Scopes - OzyRecon v8.1
"""

from fastapi import HTTPException, Security, Depends, Request
from fastapi.security.api_key import APIKeyHeader
from typing import List, Dict, Optional
from .key_store import key_store
import logging

logger = logging.getLogger("auth.dependencies")
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

import time
import random
import asyncio

async def get_current_key(header_key: str = Security(api_key_header)) -> Dict:
    """Validates the key hash and returns the key metadata (Generic errors v8.3.1)."""
    error_msg = "Unauthorized or insufficient permissions"
    
    # v8.3.1 - Constant-ish time auth failure to prevent timing leaks
    if not header_key:
        await asyncio.sleep(random.uniform(0.1, 0.3))
        raise HTTPException(status_code=403, detail=error_msg)
    
    key_data = key_store.verify_key(header_key)
    if not key_data:
        await asyncio.sleep(random.uniform(0.1, 0.3))
        raise HTTPException(status_code=403, detail=error_msg)
    
    return key_data

def require_scope(required_scope: str):
    """Dependency to enforce specific scopes with jitter on failure."""
    async def scope_checker(key_data: Dict = Depends(get_current_key)):
        error_msg = "Unauthorized or insufficient permissions"
        scopes = key_data.get("scopes", [])
        if "admin:*" in scopes:
            return key_data
        
        if required_scope not in scopes:
            logger.warning(f"Access denied for key '{key_data['name']}': Missing scope '{required_scope}'")
            # Side-channel protection
            await asyncio.sleep(random.uniform(0.1, 0.3))
            raise HTTPException(status_code=403, detail=error_msg)
        return key_data
    return scope_checker

# Helper for Audit Logging (Paso siguiente)
async def audit_request(request: Request, key_data: Dict):
    # Log details about the request
    # This will be implemented in audit.py
    pass
