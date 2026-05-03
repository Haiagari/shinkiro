"""
Cloud Bucket Discovery - OzyRecon v9.0
Scans for exposed S3, Azure Blobs, and Google Cloud Buckets related to the target.
"""

import logging
import requests
from typing import List, Dict, Any
from src.core.stealth_client import stealth_client

logger = logging.getLogger("discovery.cloud")

class CloudBucketScanner:
    """
    Scans for exposed cloud storage buckets based on domain patterns.
    """
    
    def __init__(self):
        self.providers = {
            "S3": "https://{bucket}.s3.amazonaws.com",
            "Azure": "https://{bucket}.blob.core.windows.net",
            "GCP": "https://storage.googleapis.com/{bucket}"
        }

    def scan_domain(self, domain: str) -> List[Dict[str, str]]:
        """
        Predicts bucket names based on domain and checks if they are public.
        """
        target_name = domain.split('.')[0]
        suffixes = ["", "-prod", "-dev", "-test", "-backup", "-data", "-assets", "-staging"]
        
        found_buckets = []
        
        for suffix in suffixes:
            bucket_name = f"{target_name}{suffix}"
            for provider, url_template in self.providers.items():
                url = url_template.format(bucket=bucket_name)
                
                try:
                    # Usamos stealth_client para no ser bloqueados
                    res = stealth_client.get(url, timeout=5)
                    if res:
                        if res.status_code in [200, 403]: # 403 means it exists but protected
                            status = "Public" if res.status_code == 200 else "Protected"
                            logger.info(f"Cloud Bucket found: {url} [{status}]")
                            found_buckets.append({
                                "url": url,
                                "provider": provider,
                                "status": status,
                                "name": bucket_name
                            })
                except:
                    pass
        
        return found_buckets

# Global Instance
cloud_scanner = CloudBucketScanner()
