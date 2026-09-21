"""
BGP-Shield Live RPKI ROA Synchronizer
Fetches, parses, and updates global Route Origin Authorizations (ROAs)
from public RPKI endpoints (Cloudflare RPKI / Routinator) to keep cryptographic
trust anchors updated in real-time.
"""
import ipaddress
import logging
import urllib.request
import json
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

logger = logging.getLogger("bgp_shield.rpki_sync")

CLOUDFLARE_RPKI_URL = "https://rpki.cloudflare.com/rpki.json"

class RpkiLiveSync:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.last_sync_time = None
        self.total_roas_loaded = 0
        self.unique_asns = 0

    async def sync_from_cloudflare(self, max_roas: int = 50000) -> Dict[str, Any]:
        """
        Download and parse live ROAs from Cloudflare's public RPKI cache in a background thread.
        Limits to top/first `max_roas` for fast in-memory indexing.
        """
        import asyncio
        return await asyncio.to_thread(self._sync_worker, max_roas)

    def _sync_worker(self, max_roas: int) -> Dict[str, Any]:
        logger.info(f"Starting live RPKI sync from {CLOUDFLARE_RPKI_URL}...")
        try:
            req = urllib.request.Request(
                CLOUDFLARE_RPKI_URL,
                headers={"User-Agent": "BGP-Shield-Sentinel/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())

            roas = data.get("roas", [])
            logger.info(f"Fetched {len(roas)} raw ROA records from Cloudflare RPKI.")

            new_monitored = {}
            asns_set = set()

            # Process and index ROAs
            count = 0
            for item in roas:
                prefix_str = item.get("prefix")
                asn_str = item.get("asn")
                max_len = item.get("maxLength")

                if not prefix_str or not asn_str:
                    continue

                try:
                    # Parse ASN: format can be "AS13335" or 13335
                    asn = int(str(asn_str).replace("AS", "").replace("as", ""))
                    net = ipaddress.ip_network(prefix_str)
                    
                    new_monitored[prefix_str] = {
                        "network": net,
                        "asn": asn,
                        "max_length": max_len or net.prefixlen,
                        "holder": f"RPKI {item.get('ta', 'Global').upper()}"
                    }
                    asns_set.add(asn)
                    count += 1
                    if count >= max_roas:
                        break
                except (ValueError, TypeError):
                    continue

            # Merge with existing critical monitored prefixes
            self.analyzer.update_roas(new_monitored)

            self.last_sync_time = datetime.now(timezone.utc).isoformat()
            self.total_roas_loaded = len(new_monitored)
            self.unique_asns = len(asns_set)

            logger.info(f"RPKI Live Sync complete: {self.total_roas_loaded} ROAs loaded across {self.unique_asns} ASNs.")

            return {
                "status": "SUCCESS",
                "total_roas": self.total_roas_loaded,
                "unique_asns": self.unique_asns,
                "timestamp": self.last_sync_time,
                "source": "Cloudflare Public RPKI Cache"
            }

        except Exception as e:
            logger.error(f"Failed to sync RPKI from Cloudflare: {e}")
            return {
                "status": "ERROR",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

