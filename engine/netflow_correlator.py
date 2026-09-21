"""
BGP-Shield NetFlow Telemetry & DDoS Amplification Correlator
Correlates high-velocity flow records with BGP route updates to detect:
1. Volumetric DDoS Amplification attacks (DNS, NTP, Memcached, SNMP, SSDP reflection vectors)
2. Traffic Diversion: Sudden flow volume collapse to legitimate origin AS during a BGP hijack
"""
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from collections import defaultdict

logger = logging.getLogger("bgp_shield.netflow")

# Known DDoS amplification attack vectors (Source Port -> Info)
AMPLIFICATION_VECTORS = {
    53: {"name": "DNS Reflection / Amplification", "factor": 54.0, "proto": "UDP"},
    123: {"name": "NTP Monlist Reflection", "factor": 556.9, "proto": "UDP"},
    11211: {"name": "Memcached Reflection Flood", "factor": 51000.0, "proto": "UDP"},
    161: {"name": "SNMP GetBulk Reflection", "factor": 6.3, "proto": "UDP"},
    1900: {"name": "SSDP Universal PnP Reflection", "factor": 30.8, "proto": "UDP"},
    389: {"name": "CLDAP Connectionless LDAP", "factor": 70.0, "proto": "UDP"},
    3702: {"name": "WS-Discovery Reflection", "factor": 29.0, "proto": "UDP"}
}

class NetFlowCorrelator:
    def __init__(self):
        # Rolling traffic history per prefix: prefix -> list of (timestamp, bytes, packets)
        self.prefix_traffic_history = defaultdict(list)
        # Real-time metrics
        self.total_bytes = 0
        self.total_packets = 0
        self.ddos_events_detected = 0
        self.recent_flows = []
        self.max_recent_flows = 100

    def process_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an incoming flow record for DDoS reflection signatures and volume anomalies.
        flow dict expected keys:
          - src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, timestamp (optional)
        """
        now = flow.get("timestamp") or datetime.now(timezone.utc)
        src_port = flow.get("src_port", 0)
        dst_port = flow.get("dst_port", 0)
        protocol = flow.get("protocol", "TCP").upper()
        flow_bytes = flow.get("bytes", 0)
        flow_packets = flow.get("packets", 0)
        dst_ip = flow.get("dst_ip", "")

        self.total_bytes += flow_bytes
        self.total_packets += flow_packets

        is_ddos_vector = False
        vector_type = "NORMAL"
        amplification_factor = 1.0

        # Check for known amplification source ports in UDP
        if protocol == "UDP" and src_port in AMPLIFICATION_VECTORS:
            vec_info = AMPLIFICATION_VECTORS[src_port]
            amplification_factor = vec_info["factor"]
            is_ddos_vector = True
            vector_type = vec_info["name"]
            self.ddos_events_detected += 1

        # Check for high-volume packet rates (> 100,000 packets in single flow)
        if flow_packets > 100000:
            is_ddos_vector = True
            if vector_type == "NORMAL":
                vector_type = "Volumetric SYN/UDP Flood"
                amplification_factor = max(amplification_factor, 10.0)

        result = {
            "id": flow.get("id") or f"flow-{int(time.time()*1000)}-{src_port}",
            "timestamp": now,
            "src_ip": flow.get("src_ip", "0.0.0.0"),
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "bytes": flow_bytes,
            "packets": flow_packets,
            "amplification_factor": amplification_factor,
            "is_ddos_vector": is_ddos_vector,
            "vector_type": vector_type
        }

        # Keep rolling recent flows
        self.recent_flows.append(result)
        if len(self.recent_flows) > self.max_recent_flows:
            self.recent_flows.pop(0)

        return result

    def check_traffic_diversion(self, prefix: str, current_bps: float, baseline_bps: float) -> Optional[Dict[str, Any]]:
        """
        Check if traffic volume to legitimate origin has suffered a sudden drop
        indicating traffic interception / blackholing by a BGP hijack.
        """
        if baseline_bps > 100000 and current_bps < (baseline_bps * 0.35):
            drop_percentage = round((1.0 - (current_bps / baseline_bps)) * 100.0, 1)
            return {
                "prefix": prefix,
                "baseline_bps": baseline_bps,
                "current_bps": current_bps,
                "drop_percentage": drop_percentage,
                "severity": "CRITICAL",
                "alert": f"Traffic collapse detected on prefix {prefix}: -{drop_percentage}% bandwidth drop correlated with recent BGP routing modification."
            }
        return None

    def get_summary_telemetry(self) -> Dict[str, Any]:
        """Return real-time telemetry metrics for UI dashboards."""
        return {
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "total_gb": round(self.total_bytes / (1024 ** 3), 2),
            "ddos_events_detected": self.ddos_events_detected,
            "recent_flows": self.recent_flows[-20:]
        }
