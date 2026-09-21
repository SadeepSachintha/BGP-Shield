"""
BGP-Shield AS-Path Graph & Stream Analytics Engine
Evaluates stateful AS-Path graph traversals over sliding windows to catch:
1. Sub-prefix & Exact-prefix Hijacks (RPKI ROA origin mismatch and LPM attacks)
2. Gao-Rexford Valley-Free Route Leaks (RFC 7908 violations)
3. Path Inflation & AS-Loop Poisoning
"""
import ipaddress
import logging
from typing import List, Dict, Any, Tuple, Optional
from config import (
    DEFAULT_ROA_DATABASE,
    DEFAULT_AS_RELATIONSHIPS,
    TIER1_ASNS,
    MAX_NORMAL_AS_PATH_LENGTH,
    MAX_ALLOWED_PREPEND_COUNT
)

logger = logging.getLogger("bgp_shield.analyzer")

class ASGraphAnalyzer:
    def __init__(self, roa_db: Optional[Dict[str, Any]] = None, as_relations: Optional[Dict[Tuple[int, int], str]] = None):
        self.roa_db = roa_db or DEFAULT_ROA_DATABASE
        self.as_relations = as_relations or DEFAULT_AS_RELATIONSHIPS
        # In-memory fast index for monitored prefix networks
        self.monitored_networks = {}
        self._build_prefix_index()

    def _build_prefix_index(self):
        """Pre-compute ip_network objects for fast prefix/subprefix lookups."""
        for prefix_str, roa in self.roa_db.items():
            try:
                net = ipaddress.ip_network(prefix_str)
                self.monitored_networks[prefix_str] = {
                    "network": net,
                    "asn": roa["asn"],
                    "max_length": roa.get("max_length", net.prefixlen),
                    "holder": roa.get("holder", "Unknown")
                }
            except ValueError:
                continue

    def update_roas(self, new_roas: Dict[str, Any]):
        """Dynamically update in-memory ROA index from live feeds."""
        self.monitored_networks.update(new_roas)
        logger.info(f"Updated ROA index. Total indexed prefixes: {len(self.monitored_networks)}")

    def validate_rpki(self, prefix_str: str, origin_asn: int) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Validate prefix and origin ASN against RPKI ROA records.
        Returns: (RPKI_STATUS, ROA_INFO)
        Status: VALID | INVALID_ASN | INVALID_LENGTH | NOT_FOUND
        """
        try:
            target_net = ipaddress.ip_network(prefix_str)
        except ValueError:
            return "NOT_FOUND", None

        for p_str, info in self.monitored_networks.items():
            roa_net = info["network"]
            if target_net.version != roa_net.version:
                continue
            # Check if target_net is equal or subnet of roa_net
            if target_net.subnet_of(roa_net) or target_net == roa_net:
                if origin_asn != info["asn"]:
                    return "INVALID_ASN", info
                if target_net.prefixlen > info["max_length"]:
                    return "INVALID_LENGTH", info
                return "VALID", info

        return "NOT_FOUND", None

    def check_subprefix_hijack(self, prefix_str: str, origin_asn: int) -> Optional[Dict[str, Any]]:
        """
        Detect sub-prefix hijacks where an attacker announces a more specific prefix
        (e.g., announcing /25 or /26 of a legitimate /24) to divert traffic via Longest Prefix Match (LPM).
        """
        try:
            target_net = ipaddress.ip_network(prefix_str)
        except ValueError:
            return None

        for p_str, info in self.monitored_networks.items():
            roa_net = info["network"]
            if target_net.version != roa_net.version:
                continue
            # Subnet check: target_net is strictly smaller than roa_net
            if target_net.subnet_of(roa_net) and target_net.prefixlen > roa_net.prefixlen:
                if origin_asn != info["asn"]:
                    return {
                        "type": "SUBPREFIX_HIJACK",
                        "target_prefix": prefix_str,
                        "parent_prefix": p_str,
                        "legitimate_asn": info["asn"],
                        "legitimate_holder": info["holder"],
                        "rogue_asn": origin_asn,
                        "severity": "CRITICAL",
                        "explanation": f"Subprefix {prefix_str} (/ {target_net.prefixlen}) hijacked by AS{origin_asn}. Legitimate parent is {p_str} held by AS{info['asn']} ({info['holder']}). Traffic intercepted via Longest Prefix Match."
                    }
            elif target_net == roa_net and origin_asn != info["asn"]:
                return {
                    "type": "EXACT_PREFIX_HIJACK",
                    "target_prefix": prefix_str,
                    "parent_prefix": p_str,
                    "legitimate_asn": info["asn"],
                    "legitimate_holder": info["holder"],
                    "rogue_asn": origin_asn,
                    "severity": "CRITICAL",
                    "explanation": f"Prefix {prefix_str} unauthorized announcement by AS{origin_asn}. Legitimate origin is AS{info['asn']} ({info['holder']})."
                }

        return None

    def get_as_relationship(self, as_a: int, as_b: int) -> str:
        """
        Infer AS relationship between AS_A and AS_B:
        - C2P: Customer to Provider
        - P2C: Provider to Customer
        - P2P: Peer to Peer
        - UNKNOWN: Default fallback
        """
        if (as_a, as_b) in self.as_relations:
            return self.as_relations[(as_a, as_b)]
        
        # Heuristic: Tier-1 ASNs are providers to non-Tier-1 ASNs
        if as_b in TIER1_ASNS and as_a not in TIER1_ASNS:
            return "C2P"
        if as_a in TIER1_ASNS and as_b not in TIER1_ASNS:
            return "P2C"
        if as_a in TIER1_ASNS and as_b in TIER1_ASNS:
            return "P2P"

        return "UNKNOWN"

    def check_valley_free_route_leak(self, as_path: List[int]) -> Optional[Dict[str, Any]]:
        """
        Evaluate AS-Path for Gao-Rexford Valley-Free model violations (RFC 7908).
        Rule: In a valid BGP path:
          - Uphill phase: 0 or more Customer-to-Provider (C2P) hops.
          - Peak phase: At most 1 Peer-to-Peer (P2P) hop.
          - Downhill phase: 0 or more Provider-to-Customer (P2C) hops.
        
        Violation (Route Leak):
          - Once downhill (P2C) or peering (P2P) occurs, the path CANNOT go uphill (C2P) or peer (P2P) again.
          - E.g. Provider -> Customer -> Provider (Hairpin Transit Leak)
          - E.g. Peer -> Customer -> Peer
        """
        if len(as_path) < 3:
            return None

        # Clean repeated prepended ASNs for transition analysis
        clean_path = []
        for asn in as_path:
            if not clean_path or clean_path[-1] != asn:
                clean_path.append(asn)

        if len(clean_path) < 3:
            return None

        downhill_or_peering_entered = False
        last_phase = "UPHILL"

        for i in range(len(clean_path) - 1):
            as_u = clean_path[i]
            as_v = clean_path[i + 1]
            rel = self.get_as_relationship(as_u, as_v)

            if rel == "P2C":
                downhill_or_peering_entered = True
                last_phase = "DOWNHILL"
            elif rel == "P2P":
                if downhill_or_peering_entered:
                    # Leak: Peering after downhill or previous peering
                    return {
                        "type": "ROUTE_LEAK_VALLEY_FREE",
                        "leak_as": as_u,
                        "hop": f"AS{as_u} -> AS{as_v}",
                        "hop_index": i,
                        "as_path": as_path,
                        "severity": "HIGH",
                        "explanation": f"RFC 7908 Route Leak: AS{as_u} re-announced route to peer AS{as_v} after already being in downhill/peering state ({last_phase})."
                    }
                downhill_or_peering_entered = True
                last_phase = "PEER"
            elif rel == "C2P":
                if downhill_or_peering_entered:
                    # Major Leak: Uphill after downhill/peering (e.g. transit leak through customer)
                    return {
                        "type": "ROUTE_LEAK_VALLEY_FREE",
                        "leak_as": as_u,
                        "hop": f"AS{as_u} -> AS{as_v}",
                        "hop_index": i,
                        "as_path": as_path,
                        "severity": "CRITICAL",
                        "explanation": f"RFC 7908 Valley-Free Violation: AS{as_u} acts as an unauthorized transit bridge between upstream providers/peers (hairpin leak to AS{as_v})."
                    }

        # Check for Tier-1 Hairpin: Tier-1 -> Non-Tier-1 -> Tier-1
        for i in range(len(clean_path) - 2):
            if clean_path[i] in TIER1_ASNS and clean_path[i+1] not in TIER1_ASNS and clean_path[i+2] in TIER1_ASNS:
                return {
                    "type": "ROUTE_LEAK_TIER1_HAIRPIN",
                    "leak_as": clean_path[i+1],
                    "hop": f"AS{clean_path[i]} -> AS{clean_path[i+1]} -> AS{clean_path[i+2]}",
                    "hop_index": i+1,
                    "as_path": as_path,
                    "severity": "CRITICAL",
                    "explanation": f"Tier-1 Transit Hairpin Leak: AS{clean_path[i+1]} is leaking transit traffic between Tier-1 carriers AS{clean_path[i]} and AS{clean_path[i+2]}."
                }

        return None

    def analyze_as_path(self, as_path: List[int], prefix: str) -> Dict[str, Any]:
        """
        Comprehensive evaluation of a BGP AS-Path and Prefix.
        Returns threat assessments, RPKI status, and anomaly flags.
        """
        if not as_path:
            return {"status": "EMPTY_PATH", "is_threat": False}

        origin_asn = as_path[-1]
        
        # 1. RPKI Validation
        rpki_status, roa_info = self.validate_rpki(prefix, origin_asn)

        # 2. Subprefix / Exact Hijack Detection
        hijack_info = self.check_subprefix_hijack(prefix, origin_asn)

        # 3. Route Leak Detection (Gao-Rexford)
        leak_info = self.check_valley_free_route_leak(as_path)

        # 4. Path Length & Prepending Anomalies
        max_prepend = 1
        current_prepend = 1
        for i in range(1, len(as_path)):
            if as_path[i] == as_path[i-1]:
                current_prepend += 1
                max_prepend = max(max_prepend, current_prepend)
            else:
                current_prepend = 1

        is_inflated = len(as_path) > MAX_NORMAL_AS_PATH_LENGTH
        has_excessive_prepend = max_prepend > MAX_ALLOWED_PREPEND_COUNT

        # Severity determination
        is_threat = bool(hijack_info or leak_info or rpki_status in ("INVALID_ASN", "INVALID_LENGTH"))
        severity = "INFO"
        if hijack_info:
            severity = hijack_info.get("severity", "CRITICAL")
        elif leak_info:
            severity = leak_info.get("severity", "HIGH")
        elif rpki_status == "INVALID_ASN":
            severity = "HIGH"
        elif rpki_status == "INVALID_LENGTH":
            severity = "MEDIUM"
        elif is_inflated or has_excessive_prepend:
            severity = "LOW"

        return {
            "origin_asn": origin_asn,
            "prefix": prefix,
            "path_length": len(as_path),
            "rpki_status": rpki_status,
            "roa_info": roa_info,
            "is_threat": is_threat,
            "severity": severity,
            "is_hijack": bool(hijack_info),
            "hijack_info": hijack_info,
            "is_leak": bool(leak_info),
            "leak_info": leak_info,
            "is_inflated": is_inflated,
            "max_prepend": max_prepend,
            "has_excessive_prepend": has_excessive_prepend
        }
