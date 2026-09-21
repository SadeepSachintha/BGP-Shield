"""
Unit tests for NetFlow v9 UDP parser and binary packet builder.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netflow_udp_collector import NetFlowV9Parser

def test_netflow_v9_binary_roundtrip():
    test_flows = [
        {
            "src_ip": "198.51.100.15",
            "dst_ip": "8.8.8.8",
            "src_port": 11211,
            "dst_port": 54321,
            "protocol": "UDP",
            "packets": 5000,
            "bytes": 5000000
        },
        {
            "src_ip": "203.0.113.88",
            "dst_ip": "1.1.1.1",
            "src_port": 123,
            "dst_port": 43210,
            "protocol": "UDP",
            "packets": 1200,
            "bytes": 1200000
        }
    ]

    # Build binary datagram
    packet = NetFlowV9Parser.build_test_packet(test_flows)
    assert len(packet) > 20

    # Parse back
    parsed = NetFlowV9Parser.parse_packet(packet)
    assert len(parsed) == 2
    assert parsed[0]["src_ip"] == "198.51.100.15"
    assert parsed[0]["dst_ip"] == "8.8.8.8"
    assert parsed[0]["src_port"] == 11211
    assert parsed[0]["protocol"] == "UDP"
    assert parsed[0]["bytes"] == 5000000
    assert parsed[1]["src_port"] == 123
