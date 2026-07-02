"""
Rate Limiter - PromptWall v8.1
Controlled access by API Key and IP address.
"""

import time
from collections import defaultdict
from fastapi import HTTPException, Request, Depends
from typing import Dict, Tuple
from .dependencies import get_current_key

class RateLimiter:
    def __init__(self):
        # buckets: { (key_name, ip): [timestamps] }
        self.buckets: Dict[Tuple[str, str], list] = defaultdict(list)

    def check_limit(self, request: Request, key_data: Dict):
        now = time.time()
        key_name = key_data["name"]
        ip = request.client.host if request.client else "unknown"
        limit = key_data.get("rate_limit_per_min", 60)
        
        bucket_id = (key_name, ip)
        
        # Clean old timestamps
        self.buckets[bucket_id] = [t for t in self.buckets[bucket_id] if t > now - 60]
        
        if len(self.buckets[bucket_id]) >= limit:
            raise HTTPException(
                status_code=429, 
                detail=f"Rate limit exceeded: {limit} requests per minute allowed for this key/IP."
            )
        
        self.buckets[bucket_id].append(now)

# Global Instance
rate_limiter = RateLimiter()

def rate_limit_dependency(request: Request, key_data: Dict = Depends(get_current_key)):
    rate_limiter.check_limit(request, key_data)
    return key_data
