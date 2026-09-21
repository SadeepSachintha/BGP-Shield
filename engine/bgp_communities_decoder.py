"""
BGP Communities Decoder (RFC 1997 & RFC 8092 Large Communities)
Decodes standard and large BGP community tags into human-readable routing actions,
traffic engineering scopes, and security implications for Tier-1 and major cloud ASNs.
"""
from typing import Dict, Any, List, Optional

# RFC 1997 Well-Known Standard Communities
WELL_KNOWN_COMMUNITIES = {
    "65535:65281": {
        "action": "NO_EXPORT",
        "category": "ACTION_NO_EXPORT",
        "scope": "Confederation / Outside Local AS",
        "description": "Do not advertise route to external BGP peers outside the local AS or BGP confederation (RFC 1997).",
        "security_implication": "Route propagation intentionally restricted to internal / direct transit."
    },
    "65535:65282": {
        "action": "NO_ADVERTISE",
        "category": "ACTION_NO_ADVERTISE",
        "scope": "All BGP Peers",
        "description": "Do not advertise route to any BGP peer whatsoever (RFC 1997).",
        "security_implication": "Strictly local route; announcement beyond border indicates severe leak."
    },
    "65535:65283": {
        "action": "NO_EXPORT_SUBCONFED",
        "category": "ACTION_NO_EXPORT",
        "scope": "Sub-Confederation",
        "description": "Do not advertise to external peers, including peers in other member ASNs within a confederation (RFC 1997).",
        "security_implication": "Confined to member sub-AS."
    },
    "65535:666": {
        "action": "BLACKHOLE",
        "category": "ACTION_BLACKHOLE",
        "scope": "Border Edge Routers",
        "description": "Remotely Triggered Black Hole (RTBH). Border routers will silently discard traffic to this prefix (RFC 7999).",
        "security_implication": "Active DDoS defense trigger; traffic to this prefix is dropped at ingress."
    },
    "65535:0": {
        "action": "GRACEFUL_SHUTDOWN",
        "category": "MAINTENANCE",
        "scope": "BGP Peers",
        "description": "BGP Graceful Shutdown. Signals peers that session is undergoing scheduled maintenance (RFC 8326).",
        "security_implication": "Planned maintenance; traffic should shift to alternate paths."
    }
}

# Major Provider Large Community Dictionaries (RFC 8092)
# Structure: ASN -> (Action/Function -> Description/Category)
LARGE_COMMUNITIES_DICT = {
    174: {  # Cogent Communications
        "name": "Cogent Communications",
        "actions": {
            ("999", "0"): {"action": "Do Not Export to Tier-1 Peers", "category": "ACTION_NO_EXPORT", "scope": "Tier-1 Carriers"},
            ("990", "0"): {"action": "Do Not Export to Any Peer", "category": "ACTION_NO_EXPORT", "scope": "All Peers"},
            ("10", "70"): {"action": "Set Local Preference: 70 (Low)", "category": "ACTION_LOCAL_PREF", "scope": "Cogent Core"},
            ("10", "140"): {"action": "Set Local Preference: 140 (Customer High)", "category": "ACTION_LOCAL_PREF", "scope": "Cogent Core"},
            ("3001", "0"): {"action": "Prepend AS174 1x to all peers", "category": "ACTION_PREPEND", "scope": "Global"},
            ("3002", "0"): {"action": "Prepend AS174 2x to all peers", "category": "ACTION_PREPEND", "scope": "Global"},
            ("21", "1"): {"action": "Ingested in North America", "category": "GEO_LOCATION", "scope": "Region: NA"},
            ("21", "2"): {"action": "Ingested in Europe", "category": "GEO_LOCATION", "scope": "Region: EU"},
        }
    },
    3356: {  # Lumen / CenturyLink
        "name": "Lumen Technologies",
        "actions": {
            ("100", "1"): {"action": "Set Local Preference: 70 (Deprioritize)", "category": "ACTION_LOCAL_PREF", "scope": "Lumen Core"},
            ("100", "2"): {"action": "Set Local Preference: 80", "category": "ACTION_LOCAL_PREF", "scope": "Lumen Core"},
            ("100", "3"): {"action": "Set Local Preference: 90", "category": "ACTION_LOCAL_PREF", "scope": "Lumen Core"},
            ("666", "0"): {"action": "Blackhole at Lumen Border", "category": "ACTION_BLACKHOLE", "scope": "Lumen Edge"},
            ("2001", "1"): {"action": "Ingested in North America (US-East)", "category": "GEO_LOCATION", "scope": "Region: US-East"},
            ("2001", "2"): {"action": "Ingested in North America (US-West)", "category": "GEO_LOCATION", "scope": "Region: US-West"},
            ("2002", "1"): {"action": "Ingested in Europe", "category": "GEO_LOCATION", "scope": "Region: Europe"},
            ("2003", "1"): {"action": "Ingested in Asia-Pacific", "category": "GEO_LOCATION", "scope": "Region: APAC"}
        }
    },
    1299: {  # Arelion (formerly Telia Carrier)
        "name": "Arelion",
        "actions": {
            ("999", "0"): {"action": "Do Not Export to Peers", "category": "ACTION_NO_EXPORT", "scope": "Arelion Peers"},
            ("3000", "1"): {"action": "Prepend AS1299 1x", "category": "ACTION_PREPEND", "scope": "Global"},
            ("3000", "2"): {"action": "Prepend AS1299 2x", "category": "ACTION_PREPEND", "scope": "Global"}
        }
    },
    13335: {  # Cloudflare
        "name": "Cloudflare",
        "actions": {
            ("10001", "1"): {"action": "Cloudflare Edge PoP: North America", "category": "GEO_LOCATION", "scope": "Cloudflare NA PoPs"},
            ("10002", "1"): {"action": "Cloudflare Edge PoP: Europe", "category": "GEO_LOCATION", "scope": "Cloudflare EU PoPs"},
            ("10003", "1"): {"action": "Cloudflare Edge PoP: Asia-Pacific", "category": "GEO_LOCATION", "scope": "Cloudflare APAC PoPs"},
            ("20000", "1"): {"action": "Anycast Route Steering Tier-1 Priority", "category": "TRAFFIC_ENG", "scope": "Global Anycast"}
        }
    },
    15169: {  # Google
        "name": "Google",
        "actions": {
            ("1000", "1"): {"action": "Google Core Backbone Ingress", "category": "INFORMATIONAL", "scope": "Google Core"},
            ("1000", "2"): {"action": "Google Edge PoP Ingress", "category": "GEO_LOCATION", "scope": "Google Edge"}
        }
    }
}

class BgpCommunitiesDecoder:
    """Decoder for RFC 1997 and RFC 8092 Large BGP Communities."""

    @staticmethod
    def decode_community(community_str: str) -> Dict[str, Any]:
        """Decode a single standard or large community string."""
        clean_str = community_str.strip()

        # Check RFC 1997 Well-Known Communities
        if clean_str in WELL_KNOWN_COMMUNITIES:
            info = WELL_KNOWN_COMMUNITIES[clean_str]
            return {
                "raw": clean_str,
                "type": "STANDARD_RFC1997",
                "category": info["category"],
                "action": info["action"],
                "scope": info["scope"],
                "description": info["description"],
                "security_implication": info["security_implication"],
                "asn": None
            }

        parts = clean_str.split(":")

        # RFC 8092 Large Community (ASN:Function:Parameter - 3 parts)
        if len(parts) == 3:
            try:
                asn = int(parts[0])
                fn = parts[1]
                param = parts[2]

                provider = LARGE_COMMUNITIES_DICT.get(asn)
                if provider:
                    action_info = provider["actions"].get((fn, param))
                    if action_info:
                        return {
                            "raw": clean_str,
                            "type": "LARGE_RFC8092",
                            "asn": asn,
                            "provider": provider["name"],
                            "category": action_info["category"],
                            "action": action_info["action"],
                            "scope": action_info["scope"],
                            "description": f"{provider['name']} Large Community: {action_info['action']}",
                            "security_implication": (
                                "Blackhole traffic drop" if action_info["category"] == "ACTION_BLACKHOLE"
                                else "Restricts route export to peers" if action_info["category"] == "ACTION_NO_EXPORT"
                                else "Traffic engineering or geographic steering"
                            )
                        }

                # Generic RFC 8092 fallback
                return {
                    "raw": clean_str,
                    "type": "LARGE_RFC8092",
                    "asn": asn,
                    "provider": provider["name"] if provider else f"AS{asn}",
                    "category": "CUSTOM_LARGE_COMMUNITY",
                    "action": f"Function {fn} (Parameter {param})",
                    "scope": f"AS{asn} Domain",
                    "description": f"RFC 8092 Large Community defined by AS{asn}.",
                    "security_implication": "Autonomous System specific policy action."
                }
            except (ValueError, TypeError):
                pass

        # Standard 2-part community (ASN:Value)
        if len(parts) == 2:
            try:
                asn = int(parts[0])
                val = int(parts[1])

                # Check known blackhole patterns (e.g. ASN:666)
                if val == 666:
                    return {
                        "raw": clean_str,
                        "type": "STANDARD_RFC1997",
                        "asn": asn,
                        "category": "ACTION_BLACKHOLE",
                        "action": f"RTBH Blackhole at AS{asn}",
                        "scope": f"AS{asn} Border",
                        "description": f"Remotely Triggered Black Hole requested for AS{asn} border routers.",
                        "security_implication": "Traffic to this prefix is discarded at ingress."
                    }

                return {
                    "raw": clean_str,
                    "type": "STANDARD_RFC1997",
                    "asn": asn,
                    "category": "CUSTOM_STANDARD_COMMUNITY",
                    "action": f"AS{asn} Value {val}",
                    "scope": f"AS{asn} Peering",
                    "description": f"Standard BGP community defined by AS{asn}.",
                    "security_implication": "Standard route policy or local preference tag."
                }
            except (ValueError, TypeError):
                pass

        # Unrecognized format
        return {
            "raw": clean_str,
            "type": "UNKNOWN",
            "category": "UNKNOWN",
            "action": "Unparsed Community",
            "scope": "Unknown",
            "description": f"Unrecognized BGP community format '{clean_str}'.",
            "security_implication": "None identified."
        }

    @classmethod
    def decode_communities_list(cls, communities: List[str]) -> List[Dict[str, Any]]:
        """Decode a list of community strings."""
        if not communities:
            return []
        return [cls.decode_community(c) for c in communities]

    @classmethod
    def analyze_route_communities(cls, communities: List[str]) -> Dict[str, Any]:
        """Analyze a collection of communities on an announcement for security flags."""
        decoded = cls.decode_communities_list(communities)
        has_blackhole = any(d["category"] == "ACTION_BLACKHOLE" for d in decoded)
        has_no_export = any(d["category"] == "ACTION_NO_EXPORT" for d in decoded)
        has_geo_tag = any(d["category"] == "GEO_LOCATION" for d in decoded)
        has_local_pref = any(d["category"] == "ACTION_LOCAL_PREF" for d in decoded)

        summary_actions = [d["action"] for d in decoded if d["action"] != "Unparsed Community"]

        return {
            "total_communities": len(communities),
            "decoded_communities": decoded,
            "has_blackhole": has_blackhole,
            "has_no_export": has_no_export,
            "has_geo_tag": has_geo_tag,
            "has_local_pref": has_local_pref,
            "summary_actions": summary_actions,
            "security_alert": (
                "CRITICAL: Route is marked with BLACKHOLE community (traffic discarded)" if has_blackhole
                else "RESTRICTED: Route is tagged with NO_EXPORT (should not propagate beyond direct peer)" if has_no_export
                else "NORMAL: Standard policy and traffic engineering communities"
            )
        }
