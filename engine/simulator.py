"""
BGP-Shield Attack Scenario & Chaos Simulation Engine
Generates realistic, high-impact BGP security incidents and NetFlow anomalies for testing,
verification, and real-time operational demonstrations.
"""
import time
import random
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

class AttackSimulator:
    def __init__(self, analyzer, netflow_correlator, db_manager):
        self.analyzer = analyzer
        self.netflow_correlator = netflow_correlator
        self.db_manager = db_manager

    def simulate_subprefix_hijack(self) -> Dict[str, Any]:
        """
        Simulate a Sub-prefix Hijack attack (similar to the famous Amazon Route 53 / MyEtherWallet hijack).
        Attacker announces /25 of OpenDNS /24, stealing DNS resolution traffic via Longest Prefix Match.
        """
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        target_prefix = "208.67.222.0/25"
        legit_parent = "208.67.222.0/24"
        rogue_asn = 4761  # Simulated Rogue Origin
        legit_asn = 36692  # Cisco OpenDNS
        as_path = [174, 3356, rogue_asn]

        # 1. Analyze with AS Graph Analyzer
        analysis = self.analyzer.analyze_as_path(as_path, target_prefix)

        # 2. Build BGP Event
        bgp_event = {
            "id": f"bgp-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "ANNOUNCE",
            "peer_ip": "198.32.160.1",
            "peer_asn": 174,
            "prefix": target_prefix,
            "origin_asn": rogue_asn,
            "as_path": as_path,
            "path_length": len(as_path),
            "rpki_status": analysis["rpki_status"],
            "is_leak": analysis["is_leak"],
            "leak_type": analysis["leak_info"]["type"] if analysis["leak_info"] else "NONE",
            "is_hijack": True,
            "hijack_type": "SUBPREFIX_HIJACK",
            "severity": "CRITICAL",
            "details": analysis
        }
        self.db_manager.insert_bgp_event(bgp_event)

        # Record topology links
        self.db_manager.record_as_link(174, 3356, "P2P")
        self.db_manager.record_as_link(3356, rogue_asn, "C2P")

        # 3. Simulate NetFlow telemetry diversion
        diverted_flows = []
        for _ in range(5):
            flow = {
                "src_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "dst_ip": f"208.67.222.{random.randint(1, 126)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": 53,
                "protocol": "UDP",
                "bytes": random.randint(500000, 2500000),
                "packets": random.randint(4000, 25000),
            }
            proc_flow = self.netflow_correlator.process_flow(flow)
            self.db_manager.insert_netflow_record(proc_flow)
            diverted_flows.append(proc_flow)

        # 4. Create Incident Record
        incident = {
            "id": incident_id,
            "incident_type": "SUBPREFIX_HIJACK",
            "severity": "CRITICAL",
            "target_prefix": target_prefix,
            "victim_asn": legit_asn,
            "victim_name": "Cisco OpenDNS",
            "attacker_asn": rogue_asn,
            "attacker_name": "Indosat Ooredoo (Rogue Route Injector)",
            "status": "DETECTED",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "details_json": {
                "legitimate_parent": legit_parent,
                "as_path": as_path,
                "rpki_status": analysis["rpki_status"],
                "mitigation_recommended": "BGP Flowspec drop /25 or announce covering /25 from legitimate AS36692",
                "diverted_flow_sample": diverted_flows
            }
        }
        self.db_manager.record_incident(incident)

        return {
            "incident": incident,
            "bgp_event": bgp_event,
            "analysis": analysis
        }

    def simulate_route_leak(self) -> Dict[str, Any]:
        """
        Simulate a Gao-Rexford Valley-Free Route Leak (RFC 7908).
        Transit ISP AS37282 leaks Cloudflare (AS13335) routes learned from Lumen (AS3356)
        to Cogent (AS174), creating a Provider -> Customer -> Provider hairpin leak.
        """
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        target_prefix = "1.1.1.0/24"
        victim_asn = 13335  # Cloudflare
        leaker_asn = 37282  # MainOne
        # Path: Cogent(174) -> MainOne(37282) -> Lumen(3356) -> Cloudflare(13335)
        as_path = [174, leaker_asn, 3356, victim_asn]

        analysis = self.analyzer.analyze_as_path(as_path, target_prefix)

        bgp_event = {
            "id": f"bgp-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "ANNOUNCE",
            "peer_ip": "154.25.1.1",
            "peer_asn": 174,
            "prefix": target_prefix,
            "origin_asn": victim_asn,
            "as_path": as_path,
            "path_length": len(as_path),
            "rpki_status": analysis["rpki_status"],
            "is_leak": True,
            "leak_type": analysis["leak_info"]["type"] if analysis["leak_info"] else "ROUTE_LEAK_VALLEY_FREE",
            "is_hijack": False,
            "hijack_type": "NONE",
            "severity": "CRITICAL",
            "details": analysis
        }
        self.db_manager.insert_bgp_event(bgp_event)

        # Record topology links
        self.db_manager.record_as_link(174, leaker_asn, "P2C")
        self.db_manager.record_as_link(leaker_asn, 3356, "C2P")
        self.db_manager.record_as_link(3356, victim_asn, "P2C")

        incident = {
            "id": incident_id,
            "incident_type": "ROUTE_LEAK",
            "severity": "CRITICAL",
            "target_prefix": target_prefix,
            "victim_asn": victim_asn,
            "victim_name": "Cloudflare Edge",
            "attacker_asn": leaker_asn,
            "attacker_name": "MainOne Cable Co. (Leaking AS)",
            "status": "DETECTED",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "details_json": {
                "leak_type": "Gao-Rexford Valley-Free Violation (RFC 7908)",
                "violating_hop": f"AS{leaker_asn} (Customer) bridging AS174 and AS3356 (Providers)",
                "as_path": as_path,
                "mitigation_recommended": "Filter routes from AS37282 at AS174 edge using BGP community NO_EXPORT"
            }
        }
        self.db_manager.record_incident(incident)

        return {
            "incident": incident,
            "bgp_event": bgp_event,
            "analysis": analysis
        }

    def simulate_ddos_amplification(self) -> Dict[str, Any]:
        """
        Simulate a multi-vector volumetric DDoS amplification attack (NTP Monlist & Memcached UDP reflection).
        """
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        target_prefix = "8.8.8.0/24"
        victim_asn = 15169  # Google DNS

        flow_records = []
        vectors = [
            {"port": 123, "proto": "UDP", "name": "NTP Monlist Reflection", "factor": 556.9},
            {"port": 11211, "proto": "UDP", "name": "Memcached Reflection Flood", "factor": 51000.0},
            {"port": 53, "proto": "UDP", "name": "DNS ANY Amplification", "factor": 54.0}
        ]

        total_bytes = 0
        total_packets = 0

        for _ in range(12):
            vec = random.choice(vectors)
            f_bytes = random.randint(15000000, 85000000)
            f_pkts = random.randint(120000, 650000)
            total_bytes += f_bytes
            total_packets += f_pkts

            flow = {
                "src_ip": f"198.51.100.{random.randint(1, 254)}",
                "dst_ip": f"8.8.8.{random.randint(1, 10)}",
                "src_port": vec["port"],
                "dst_port": random.randint(1024, 65535),
                "protocol": vec["proto"],
                "bytes": f_bytes,
                "packets": f_pkts,
                "amplification_factor": vec["factor"],
                "is_ddos_vector": True,
                "vector_type": vec["name"]
            }
            proc_flow = self.netflow_correlator.process_flow(flow)
            self.db_manager.insert_netflow_record(proc_flow)
            flow_records.append(proc_flow)

        incident = {
            "id": incident_id,
            "incident_type": "DDOS_AMPLIFICATION",
            "severity": "HIGH",
            "target_prefix": target_prefix,
            "victim_asn": victim_asn,
            "victim_name": "Google Public DNS",
            "attacker_asn": 0,
            "attacker_name": "Distributed Amplification Reflectors (NTP/Memcached)",
            "status": "DETECTED",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "details_json": {
                "peak_bandwidth_gbps": round((total_bytes * 8) / (1024**3), 2),
                "total_packets": total_packets,
                "detected_vectors": [v["name"] for v in vectors],
                "mitigation_recommended": "Deploy BGP Flowspec rule: discard UDP traffic with src-port 123, 11211 to target prefix"
            }
        }
        self.db_manager.record_incident(incident)

        return {
            "incident": incident,
            "flow_records": flow_records,
            "total_bytes": total_bytes
        }
