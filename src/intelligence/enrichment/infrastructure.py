"""
Infrastructure Enrichment Engine (OzyRecon v7 - Phase 2)
Handles ASN lookups, Cloud Detection, and Organization identification.
"""

import socket
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class InfraEnricher:
    """
    Enriches IP addresses with ASN and Cloud provider context.
    """
    
    # Simple Cloud Provider IP Ranges or Signatures (v7 Alpha)
    # In a full v7, this would use a more robust range matching system.
    CLOUD_SIGNATURES = {
        "Amazon.com": "aws",
        "Google": "gcp",
        "Microsoft": "azure",
        "Cloudflare": "cloudflare",
        "DigitalOcean": "digitalocean",
        "Akamai": "akamai",
        "Linode": "linode"
    }

    def __init__(self):
        self.cache = {}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Retrieves infrastructure context for a given IP.
        """
        if ip in self.cache:
            return self.cache[ip]

        data = {
            "asn": None,
            "asn_organization": "Unknown",
            "cloud_provider": None,
            "is_cloud": False
        }

        try:
            # 1. Reverse DNS Lookup (Basic Org identification)
            try:
                host_info = socket.gethostbyaddr(ip)
                ptr_record = host_info[0]
                # Try to infer cloud from PTR
                for sig, provider in self.CLOUD_SIGNATURES.items():
                    if provider in ptr_record.lower():
                        data["cloud_provider"] = provider
                        data["is_cloud"] = True
            except (socket.herror, socket.error):
                pass

            # 2. ASN Lookup via DNS (Team Cymru)
            # Format: <reversed-ip>.origin.asn.cymru.com
            asn_data = self._lookup_asn_cymru(ip)
            if asn_data:
                data.update(asn_data)
                
                # Refine Cloud Detection based on ASN Org
                for sig, provider in self.CLOUD_SIGNATURES.items():
                    if sig.lower() in data["asn_organization"].lower():
                        data["cloud_provider"] = provider
                        data["is_cloud"] = True

        except Exception as e:
            logger.warning(f"Failed to enrich IP {ip}: {e}")

        self.cache[ip] = data
        return data

    def _lookup_asn_cymru(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Performs a lightweight ASN lookup via Team Cymru DNS service.
        """
        try:
            # Reverse IP for DNS query
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            
            # This is a TXT query that returns "ASN | IP/Prefix | Country | Registry | Date"
            # We use basic socket resolution to keep dependencies low
            import subprocess
            cmd = ["dig", "+short", "TXT", query]
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()
            
            if not result:
                return None

            # Parse "ASN | Prefix | CC | Registry | Date"
            parts = [p.strip().replace('"', '') for p in result.split("|")]
            if len(parts) >= 1:
                asn = parts[0]
                
                # Get Org Name from ASN
                org_query = f"AS{asn}.asn.cymru.com"
                org_cmd = ["dig", "+short", "TXT", org_query]
                org_result = subprocess.check_output(org_cmd, stderr=subprocess.STDOUT).decode().strip()
                
                org_name = "Unknown"
                if org_result:
                    # ASN | CC | Registry | Date | Org Name
                    org_parts = [p.strip().replace('"', '') for p in org_result.split("|")]
                    if len(org_parts) >= 5:
                        org_name = org_parts[4]

                return {
                    "asn": int(asn) if asn.isdigit() else None,
                    "asn_organization": org_name
                }
        except Exception:
            pass
        return None

# Global Instance
infra_enricher = InfraEnricher()
