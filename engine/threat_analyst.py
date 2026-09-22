"""
BGP-Shield Autonomous AI Threat Analyst & Intent Classifier
Classifies BGP security incidents into operational blunders vs targeted adversarial campaigns,
aligns incidents with the MITRE ATT&CK Enterprise Matrix, and calculates attribution confidence.
"""

from typing import Dict, Any, List, Optional
import datetime


class ThreatAnalyst:
    """
    Evaluates BGP routing anomalies and NetFlow telemetry to attribute intent,
    estimate threat actor capabilities, and recommend containment playbooks.
    """

    # Known state-affiliated or high-risk transit Autonomous Systems
    STATE_ALIGNED_ASNS = {
        12389: {"name": "Rostelecom", "country": "RU", "tier": "State-Owned Tier-1"},
        4134: {"name": "China Telecom", "country": "CN", "tier": "State-Owned Tier-1"},
        4837: {"name": "China Unicom", "country": "CN", "tier": "State-Owned Tier-1"},
        36561: {"name": "Pakistan Telecom", "country": "PK", "tier": "State-Regulated Telco"},
        2497: {"name": "IIJ", "country": "JP", "tier": "Regional Transit"},
        31133: {"name": "MegaFon", "country": "RU", "tier": "National Telco"},
        58453: {"name": "China Mobile", "country": "CN", "tier": "State-Owned Tier-1"},
    }

    # High-value financial / DNS targets
    HIGH_VALUE_TARGETS = {
        "205.251.192.0/23": "Amazon Route 53 (Authoritative DNS)",
        "205.251.194.0/23": "Amazon Route 53 (Authoritative DNS)",
        "1.1.1.0/24": "Cloudflare Public DNS Resolver",
        "1.0.0.0/24": "Cloudflare Public DNS Resolver",
        "8.8.8.0/24": "Google Public DNS",
        "8.8.4.0/24": "Google Public DNS",
        "208.65.152.0/22": "YouTube Video Infrastructure",
        "208.65.153.0/24": "YouTube Edge Subprefix",
        "104.16.0.0/12": "Cloudflare Edge CDN / Crypto Gateways",
    }

    def __init__(self):
        pass

    def evaluate_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs deep intent attribution and MITRE ATT&CK mapping on a BGP incident.
        """
        incident_type = incident.get("incident_type", "").upper()
        target_prefix = incident.get("target_prefix", "")
        victim_asn = int(incident.get("victim_asn", 0))
        attacker_asn = int(incident.get("attacker_asn", 0))
        rpki_status = incident.get("rpki_status", "UNKNOWN").upper()
        as_path = incident.get("as_path", [])
        if isinstance(as_path, str):
            as_path = [int(x) for x in as_path.split() if x.isdigit()]

        traffic_drop = float(incident.get("traffic_drop_pct", incident.get("traffic_loss_pct", 0.0)))
        amplification_factor = float(incident.get("amplification_factor", 1.0))
        netflow_surge = float(incident.get("netflow_surge_pct", 0.0))

        # 1. Calculate intent probabilities
        intent_scores = {
            "STATE_SPONSORED_INTERCEPTION": 5,
            "FINANCIAL_CRYPTO_HIJACK": 5,
            "ISP_FAT_FINGER_MISCONFIG": 15,
            "DDOS_AMPLIFICATION_ATTACK": 5,
            "MALICIOUS_SUBPREFIX_HIJACK": 10,
        }

        evidence = []
        mitre_tactics = []

        # Feature A: Attacker ASN reputation & state alignment
        is_state_aligned = attacker_asn in self.STATE_ALIGNED_ASNS
        if is_state_aligned:
            state_info = self.STATE_ALIGNED_ASNS[attacker_asn]
            intent_scores["STATE_SPONSORED_INTERCEPTION"] += 50
            evidence.append({
                "category": "AS_ATTRIBUTION",
                "indicator": f"Rogue ASN {attacker_asn} ({state_info['name']})",
                "detail": f"Attacker belongs to a foreign state-regulated or state-owned telecom entity ({state_info['country']}).",
                "severity": "CRITICAL"
            })
            mitre_tactics.append({
                "tactic": "Resource Development",
                "technique_id": "T1584.004",
                "technique_name": "Compromise Infrastructure: DNS/BGP Server",
                "description": "Adversary leverages state-level routing autonomy or co-opted national telco peerings to hijack Internet traffic."
            })

        # Feature B: High-Value Target Check
        is_high_value = target_prefix in self.HIGH_VALUE_TARGETS
        if is_high_value:
            target_desc = self.HIGH_VALUE_TARGETS[target_prefix]
            intent_scores["FINANCIAL_CRYPTO_HIJACK"] += 45
            intent_scores["STATE_SPONSORED_INTERCEPTION"] += 20
            evidence.append({
                "category": "TARGET_SECTOR",
                "indicator": f"High-Value Infrastructure Target: {target_prefix}",
                "detail": f"Victim prefix maps to critical infrastructure: {target_desc}.",
                "severity": "CRITICAL"
            })
            mitre_tactics.append({
                "tactic": "Credential Access / Collection",
                "technique_id": "T1557.000",
                "technique_name": "Adversary-in-the-Middle (AiTM)",
                "description": "Traffic redirected to rogue infrastructure to intercept encrypted credentials, DNS queries, or crypto transactions."
            })

        # Feature C: Incident Type Analysis
        if "HIJACK" in incident_type or "SUBPREFIX" in incident_type:
            intent_scores["MALICIOUS_SUBPREFIX_HIJACK"] += 35
            intent_scores["FINANCIAL_CRYPTO_HIJACK"] += 20
            evidence.append({
                "category": "ROUTING_VECTOR",
                "indicator": "More-Specific Prefix Advertised (/24 or narrower)",
                "detail": "Longest-prefix match algorithm forces global traffic toward rogue origin regardless of AS path length.",
                "severity": "HIGH"
            })

        if "GAO_REXFORD" in incident_type or "LEAK" in incident_type:
            intent_scores["ISP_FAT_FINGER_MISCONFIG"] += 60
            evidence.append({
                "category": "ROUTING_VECTOR",
                "indicator": "Gao-Rexford Peer-to-Peer / Provider-to-Provider Leak",
                "detail": "Transit routing policy violation typical of BGP route optimizer misconfigurations or multihomed stub export errors.",
                "severity": "HIGH"
            })
            mitre_tactics.append({
                "tactic": "Impact",
                "technique_id": "T1565.002",
                "technique_name": "Transmitted Data Manipulation",
                "description": "Route leak forces sub-optimal transit through unauthorized intermediate networks, degrading availability."
            })

        if "DDOS" in incident_type or amplification_factor > 2.0 or netflow_surge > 200:
            intent_scores["DDOS_AMPLIFICATION_ATTACK"] += 70
            evidence.append({
                "category": "TELEMETRY_DELTA",
                "indicator": f"NetFlow Volumetric Surge (+{netflow_surge:.1f}%, Factor: {amplification_factor:.1f}x)",
                "detail": "Massive UDP packet flood detected crossing transit interfaces, indicating reflection amplification.",
                "severity": "CRITICAL"
            })
            mitre_tactics.append({
                "tactic": "Impact",
                "technique_id": "T1498.001",
                "technique_name": "Direct Network Denial of Service: Volumetric",
                "description": "Adversary floods network interfaces to saturate line cards and induce service blackouts."
            })

        # Feature D: RPKI Validation Cryptanalysis
        if rpki_status == "INVALID":
            intent_scores["STATE_SPONSORED_INTERCEPTION"] += 15
            intent_scores["MALICIOUS_SUBPREFIX_HIJACK"] += 20
            evidence.append({
                "category": "CRYPTOGRAPHIC_INTEGRITY",
                "indicator": "RPKI ROA Validation: INVALID",
                "detail": "Cryptographic Route Origin Authorization explicitly disallows ASN from advertising this prefix.",
                "severity": "HIGH"
            })
        elif rpki_status == "VALID":
            # If RPKI is valid, likely a subtle route leak or AS-path manipulation rather than origin hijack
            intent_scores["ISP_FAT_FINGER_MISCONFIG"] += 25
            intent_scores["MALICIOUS_SUBPREFIX_HIJACK"] -= 15

        # Feature E: AS Path Length & Transit Detour Anomaly
        if len(as_path) >= 5:
            evidence.append({
                "category": "PATH_TOPOLOGY",
                "indicator": f"Anomalous AS Path Inflation ({len(as_path)} Hops)",
                "detail": f"Path contains deliberate or accidental transit inflation: {' -> '.join(str(a) for a in as_path)}.",
                "severity": "MEDIUM"
            })

        # Normalize intent probabilities to sum to 100%
        total_score = sum(intent_scores.values())
        intent_probabilities = {
            k: round((v / total_score) * 100, 1) for k, v in intent_scores.items()
        }

        # Determine Primary Intent
        primary_intent = max(intent_probabilities.items(), key=lambda x: x[1])[0]
        confidence_pct = intent_probabilities[primary_intent]

        # Calculate Threat Severity Index (0-100)
        base_threat = 40
        if primary_intent == "STATE_SPONSORED_INTERCEPTION":
            base_threat = 92
        elif primary_intent == "FINANCIAL_CRYPTO_HIJACK":
            base_threat = 88
        elif primary_intent == "DDOS_AMPLIFICATION_ATTACK":
            base_threat = 82
        elif primary_intent == "MALICIOUS_SUBPREFIX_HIJACK":
            base_threat = 78
        elif primary_intent == "ISP_FAT_FINGER_MISCONFIG":
            base_threat = 52

        # Adjust for traffic loss & RPKI
        if traffic_drop > 40:
            base_threat = min(100, base_threat + 10)
        if rpki_status == "INVALID":
            base_threat = min(100, base_threat + 5)

        # Tactical Countermeasures based on primary intent
        countermeasures = self._generate_countermeasures(primary_intent, incident)

        # Default MITRE tactic if none added
        if not mitre_tactics:
            mitre_tactics.append({
                "tactic": "Network Manipulation",
                "technique_id": "T1584.004",
                "technique_name": "Compromise Infrastructure: DNS/BGP Server",
                "description": "Manipulation of inter-domain routing protocols to hijack or misroute Internet communications."
            })

        return {
            "incident_id": incident.get("id", "UNKNOWN"),
            "evaluated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "threat_severity_score": int(base_threat),
            "threat_rating": "CRITICAL" if base_threat >= 80 else ("HIGH" if base_threat >= 65 else "ELEVATED"),
            "primary_intent": primary_intent,
            "confidence_pct": confidence_pct,
            "intent_probabilities": intent_probabilities,
            "mitre_attack_matrix": mitre_tactics,
            "forensic_evidence": evidence,
            "strategic_countermeasures": countermeasures,
            "target_prefix": target_prefix,
            "victim_asn": victim_asn,
            "attacker_asn": attacker_asn,
            "is_state_sponsored": primary_intent == "STATE_SPONSORED_INTERCEPTION",
            "is_high_value_target": is_high_value,
        }

    def _generate_countermeasures(self, primary_intent: str, incident: Dict[str, Any]) -> List[Dict[str, str]]:
        prefix = incident.get("target_prefix", "target prefix")
        attacker_asn = incident.get("attacker_asn", "rogue ASN")

        if primary_intent == "STATE_SPONSORED_INTERCEPTION":
            return [
                {
                    "step": "1. Upstream AS-Path Filtering",
                    "action": f"Request immediate AS-Path access-list filtering from Tier-1 transits (AS174, AS3356) to drop announcements originating from AS{attacker_asn}.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "2. Emergency More-Specific Deaggregation",
                    "action": f"Advertise authorized /24 subprefixes for {prefix} across all global transit providers to re-claim longest-prefix preference.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "3. RPKI Strict Validation Enforcement",
                    "action": "Ensure all upstream peering sessions enforce RPKI Invalid Reject (RFC 6811) to drop unauthorized origin announcements at the ingress edge.",
                    "urgency": "HIGH"
                },
                {
                    "step": "4. Diplomatic / Regulatory Escalation",
                    "action": "Submit formal route hijack abuse report to RIR (RIPE NCC / ARIN / APNIC) and national CERT.",
                    "urgency": "MEDIUM"
                }
            ]
        elif primary_intent == "FINANCIAL_CRYPTO_HIJACK":
            return [
                {
                    "step": "1. Authoritative DNS Cache Invalidation",
                    "action": f"Flush public DNS resolver caches (1.1.1.1, 8.8.8.8) and invalidate poisoned DNS records for services on {prefix}.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "2. Flowspec Redirect & RTBH Blackholing",
                    "action": f"Execute BGP Flowspec redirect-to-scrubbing rule on {prefix} to inspect and cleanse inbound TCP port 443 / UDP port 53 traffic.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "3. ROA Re-Signing & MaxLength Tightening",
                    "action": "Update RPKI ROA object in RIR portal with MaxLength strictly matching advertised prefix mask.",
                    "urgency": "HIGH"
                }
            ]
        elif primary_intent == "ISP_FAT_FINGER_MISCONFIG":
            return [
                {
                    "step": "1. NOC Peering Coordination",
                    "action": f"Contact AS{attacker_asn} NOC to enforce BGP filter list and shutdown leaked transit session.",
                    "urgency": "HIGH"
                },
                {
                    "step": "2. BGP Large Community Tagging",
                    "action": "Tag outgoing announcements with RFC 8092 Large Communities (e.g. `ASN:999:0`) to forbid transit re-export.",
                    "urgency": "MEDIUM"
                },
                {
                    "step": "3. Autonomous System Provider Authorization (ASPA)",
                    "action": "Publish ASPA objects to prevent downstream multihomed stub networks from acting as transit providers.",
                    "urgency": "MEDIUM"
                }
            ]
        elif primary_intent == "DDOS_AMPLIFICATION_ATTACK":
            return [
                {
                    "step": "1. Ingress Flowspec Rate-Limiting",
                    "action": f"Deploy BGP Flowspec rule rate-limiting UDP traffic on ports 123, 53, 389, and 11211 to 10 Mbps across edge routers.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "2. Upstream RTBH Activation",
                    "action": f"Tag victim destination IP with RFC 1997 `65535:666` community to trigger upstream transit blackholing.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "3. Scrubbing Center Traffic Diversion",
                    "action": "Prepend AS-Path on direct peerings and swing GRE tunnels into DDoS mitigation scrubbing centers.",
                    "urgency": "HIGH"
                }
            ]
        else:
            return [
                {
                    "step": "1. Prefix Hijack Suppression",
                    "action": f"Issue BGP withdrawal and inject more-specific announcements for {prefix}.",
                    "urgency": "IMMEDIATE"
                },
                {
                    "step": "2. Upstream Peer Ingress Filtering",
                    "action": f"Notify transit providers to enforce strict IRR / RPKI origin filtering on AS{attacker_asn}.",
                    "urgency": "HIGH"
                }
            ]
