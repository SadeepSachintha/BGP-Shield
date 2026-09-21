"""
PeeringDB Client & Interconnection Metadata Cache
Fetches and caches peering policies, Internet Exchange Point (IXP) presences,
facility counts, and traffic profiles from the public PeeringDB API.
"""
import asyncio
import json
import logging
import urllib.request
from typing import Dict, Any, Optional

logger = logging.getLogger("bgp_shield.peeringdb")

PEERINGDB_API_URL = "https://www.peeringdb.com/api/net"

# Pre-seeded PeeringDB intelligence profiles for core Tier-1s, CDNs, and monitored ASNs
PRESEEDED_PEERINGDB_DATA = {
    174: {
        "asn": 174,
        "name": "Cogent Communications",
        "org_name": "Cogent Communications, Inc.",
        "policy_general": "Open",
        "info_type": "NSP (Tier-1 Carrier)",
        "fac_count": 485,
        "ix_count": 82,
        "ixp_presences": ["Equinix Ashburn", "AMS-IX Amsterdam", "DE-CIX Frankfurt", "LINX London", "NYIIX New York"],
        "traffic_profile": "Balanced",
        "irr_as_set": "AS-COGENT",
        "website": "https://www.cogentco.com",
        "public_peering_capacity": "400 Gbps"
    },
    3356: {
        "asn": 3356,
        "name": "Lumen Technologies",
        "org_name": "Lumen Technologies / Level 3",
        "policy_general": "Selective",
        "info_type": "NSP (Tier-1 Carrier)",
        "fac_count": 412,
        "ix_count": 64,
        "ixp_presences": ["Equinix Ashburn", "LINX London", "DE-CIX Frankfurt", "Equinix Chicago", "AMS-IX"],
        "traffic_profile": "Balanced",
        "irr_as_set": "AS-LEVEL3",
        "website": "https://www.lumen.com",
        "public_peering_capacity": "400 Gbps"
    },
    1299: {
        "asn": 1299,
        "name": "Arelion",
        "org_name": "Arelion Sweden AB (formerly Telia Carrier)",
        "policy_general": "Open",
        "info_type": "NSP (Tier-1 Carrier)",
        "fac_count": 340,
        "ix_count": 76,
        "ixp_presences": ["AMS-IX Amsterdam", "Netnod Stockholm", "DE-CIX Frankfurt", "LINX London", "Equinix Ashburn"],
        "traffic_profile": "Balanced",
        "irr_as_set": "AS-TELIANET",
        "website": "https://www.arelion.com",
        "public_peering_capacity": "400 Gbps"
    },
    13335: {
        "asn": 13335,
        "name": "Cloudflare",
        "org_name": "Cloudflare, Inc.",
        "policy_general": "Open",
        "info_type": "Content / CDN",
        "fac_count": 315,
        "ix_count": 290,
        "ixp_presences": ["AMS-IX", "DE-CIX Frankfurt", "Equinix Ashburn", "LINX", "JPIX Tokyo", "HKIX Hong Kong"],
        "traffic_profile": "Heavy Outbound",
        "irr_as_set": "AS-CLOUDFLARE",
        "website": "https://www.cloudflare.com",
        "public_peering_capacity": "1 Tbps+"
    },
    15169: {
        "asn": 15169,
        "name": "Google",
        "org_name": "Google LLC",
        "policy_general": "Open",
        "info_type": "Content / Cloud",
        "fac_count": 295,
        "ix_count": 265,
        "ixp_presences": ["Equinix Ashburn", "AMS-IX", "DE-CIX", "LINX", "Equinix Singapore"],
        "traffic_profile": "Heavy Outbound",
        "irr_as_set": "AS-GOOGLE",
        "website": "https://www.google.com",
        "public_peering_capacity": "1 Tbps+"
    },
    16509: {
        "asn": 16509,
        "name": "Amazon AWS",
        "org_name": "Amazon.com, Inc.",
        "policy_general": "Open",
        "info_type": "Content / Cloud",
        "fac_count": 260,
        "ix_count": 220,
        "ixp_presences": ["Equinix Ashburn", "AMS-IX", "DE-CIX", "LINX London"],
        "traffic_profile": "Heavy Outbound",
        "irr_as_set": "AS-AMAZON",
        "website": "https://aws.amazon.com",
        "public_peering_capacity": "1 Tbps+"
    },
    36692: {
        "asn": 36692,
        "name": "Cisco OpenDNS",
        "org_name": "Cisco Systems, Inc.",
        "policy_general": "Open",
        "info_type": "Content / Security",
        "fac_count": 48,
        "ix_count": 42,
        "ixp_presences": ["Equinix Ashburn", "AMS-IX", "DE-CIX", "LINX London", "SIX Seattle"],
        "traffic_profile": "Balanced",
        "irr_as_set": "AS-OPENDNS",
        "website": "https://www.opendns.com",
        "public_peering_capacity": "100 Gbps"
    },
    4761: {
        "asn": 4761,
        "name": "Indosat Ooredoo",
        "org_name": "PT Indosat Tbk",
        "policy_general": "Selective",
        "info_type": "NSP / Regional ISP",
        "fac_count": 18,
        "ix_count": 12,
        "ixp_presences": ["IIX Jakarta", "OpenIXP Jakarta", "Equinix Singapore"],
        "traffic_profile": "Heavy Inbound",
        "irr_as_set": "AS-INDOSAT",
        "website": "https://indosatooredoo.com",
        "public_peering_capacity": "50 Gbps"
    }
}

class PeeringDbClient:
    """Asynchronous client with local cache for PeeringDB network metadata."""

    def __init__(self):
        self._cache: Dict[int, Dict[str, Any]] = dict(PRESEEDED_PEERINGDB_DATA)

    async def get_asn_metadata(self, asn: int) -> Dict[str, Any]:
        """Fetch PeeringDB metadata for an ASN (returns pre-seeded / cached data instantly)."""
        if asn in self._cache:
            data = dict(self._cache[asn])
            data["source"] = "PeeringDB Cache"
            return data

        # If not cached, attempt live lookup in background thread
        try:
            return await asyncio.to_thread(self._fetch_from_api, asn)
        except Exception as e:
            logger.warning(f"Could not fetch PeeringDB data for AS{asn}: {e}")
            fallback = self._create_fallback(asn)
            self._cache[asn] = fallback
            return fallback

    def _fetch_from_api(self, asn: int) -> Dict[str, Any]:
        """Synchronous HTTP fetch from PeeringDB REST API."""
        url = f"{PEERINGDB_API_URL}?asn={asn}"
        req = urllib.request.Request(url, headers={"User-Agent": "BGP-Shield-Sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        nets = data.get("data", [])
        if not nets:
            return self._create_fallback(asn)

        net = nets[0]
        result = {
            "asn": asn,
            "name": net.get("name", f"AS{asn}"),
            "org_name": net.get("org_name") or net.get("name", f"AS{asn}"),
            "policy_general": net.get("policy_general", "Unknown"),
            "info_type": net.get("info_type", "NSP"),
            "fac_count": net.get("fac_count", 0),
            "ix_count": net.get("netixlan_count", 0),
            "ixp_presences": ["Global IXP Fabric"],
            "traffic_profile": net.get("traffic_profile", "Balanced"),
            "irr_as_set": net.get("irr_as_set", f"AS{asn}"),
            "website": net.get("website", ""),
            "public_peering_capacity": "Unknown",
            "source": "PeeringDB Live API"
        }
        self._cache[asn] = result
        return result

    def _create_fallback(self, asn: int) -> Dict[str, Any]:
        """Fallback when ASN is not found in PeeringDB."""
        return {
            "asn": asn,
            "name": f"AS{asn}",
            "org_name": f"Autonomous System {asn}",
            "policy_general": "Unknown",
            "info_type": "NSP / Enterprise",
            "fac_count": 1,
            "ix_count": 1,
            "ixp_presences": ["Direct Peering"],
            "traffic_profile": "Balanced",
            "irr_as_set": f"AS{asn}",
            "website": "",
            "public_peering_capacity": "10 Gbps",
            "source": "Heuristic Fallback"
        }
