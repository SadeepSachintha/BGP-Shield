"""
Unit tests for DuckDBManager columnar storage and analytics.
"""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from db_manager import DuckDBManager

@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = str(Path(temp_dir) / "test.duckdb")
    return DuckDBManager(db_path=db_path)

def test_insert_and_query_bgp_event(temp_db):
    event = {
        "id": "test-bgp-1",
        "event_type": "ANNOUNCE",
        "peer_ip": "1.2.3.4",
        "peer_asn": 174,
        "prefix": "8.8.8.0/24",
        "origin_asn": 15169,
        "as_path": [174, 3356, 15169],
        "path_length": 3,
        "rpki_status": "VALID",
        "is_leak": False,
        "is_hijack": False,
        "severity": "INFO"
    }
    temp_db.insert_bgp_event(event)
    events = temp_db.get_recent_bgp_events(limit=10)
    assert len(events) == 1
    assert events[0]["id"] == "test-bgp-1"
    assert events[0]["prefix"] == "8.8.8.0/24"
    assert events[0]["as_path"] == [174, 3356, 15169]

def test_incident_recording(temp_db):
    inc = {
        "id": "inc-test-1",
        "incident_type": "SUBPREFIX_HIJACK",
        "severity": "CRITICAL",
        "target_prefix": "208.67.222.0/25",
        "victim_asn": 36692,
        "victim_name": "Cisco OpenDNS",
        "attacker_asn": 4761,
        "attacker_name": "Indosat",
        "status": "DETECTED",
        "details_json": {"reason": "LPM Hijack"}
    }
    temp_db.record_incident(inc)
    incidents = temp_db.get_active_incidents(limit=5)
    assert len(incidents) == 1
    assert incidents[0]["id"] == "inc-test-1"
    assert incidents[0]["severity"] == "CRITICAL"

def test_topology(temp_db):
    temp_db.record_as_link(174, 3356, "P2P")
    topo = temp_db.get_topology()
    assert len(topo["nodes"]) > 0
    assert any(link["source"] == "AS174" and link["target"] == "AS3356" for link in topo["links"])
