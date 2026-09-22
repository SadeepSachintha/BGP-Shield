"""
Unit tests for BGP-Shield Autonomous AI Threat Analyst & Intent Classifier.
"""

import pytest
import sys
import os

# Add engine directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from threat_analyst import ThreatAnalyst


def test_state_sponsored_classification():
    analyst = ThreatAnalyst()
    incident = {
        "id": "INC-TEST-001",
        "incident_type": "SUBPREFIX_HIJACK",
        "target_prefix": "104.16.0.0/12",
        "victim_asn": 13335,
        "attacker_asn": 12389,  # Rostelecom (State-owned)
        "rpki_status": "INVALID",
        "traffic_drop_pct": 65.0,
        "as_path": [12389, 13335]
    }
    result = analyst.evaluate_incident(incident)

    assert result["primary_intent"] == "STATE_SPONSORED_INTERCEPTION"
    assert result["threat_severity_score"] >= 80
    assert result["is_state_sponsored"] is True
    assert any("T1584.004" in m["technique_id"] for m in result["mitre_attack_matrix"])
    assert len(result["strategic_countermeasures"]) > 0


def test_financial_crypto_hijack_classification():
    analyst = ThreatAnalyst()
    incident = {
        "id": "INC-TEST-002",
        "incident_type": "SUBPREFIX_HIJACK",
        "target_prefix": "205.251.192.0/23",  # Amazon Route 53 (High value)
        "victim_asn": 16509,
        "attacker_asn": 10297,  # eNet
        "rpki_status": "INVALID",
        "traffic_drop_pct": 80.0,
        "as_path": [6939, 10297]
    }
    result = analyst.evaluate_incident(incident)

    assert result["primary_intent"] == "FINANCIAL_CRYPTO_HIJACK"
    assert result["is_high_value_target"] is True
    assert any("T1557.000" in m["technique_id"] for m in result["mitre_attack_matrix"])


def test_fat_finger_misconfig_classification():
    analyst = ThreatAnalyst()
    incident = {
        "id": "INC-TEST-003",
        "incident_type": "GAO_REXFORD_LEAK",
        "target_prefix": "198.51.100.0/24",
        "victim_asn": 15169,
        "attacker_asn": 33154,  # DQE
        "rpki_status": "VALID",
        "traffic_drop_pct": 20.0,
        "as_path": [7018, 39653, 33154, 15169]
    }
    result = analyst.evaluate_incident(incident)

    assert result["primary_intent"] == "ISP_FAT_FINGER_MISCONFIG"
    assert result["threat_severity_score"] < 80
    assert any("T1565.002" in m["technique_id"] for m in result["mitre_attack_matrix"])


def test_ddos_amplification_classification():
    analyst = ThreatAnalyst()
    incident = {
        "id": "INC-TEST-004",
        "incident_type": "DDOS_AMPLIFICATION",
        "target_prefix": "203.0.113.0/24",
        "victim_asn": 36692,
        "attacker_asn": 4761,
        "amplification_factor": 15.5,
        "netflow_surge_pct": 600.0,
        "traffic_drop_pct": 90.0,
    }
    result = analyst.evaluate_incident(incident)

    assert result["primary_intent"] == "DDOS_AMPLIFICATION_ATTACK"
    assert any("T1498.001" in m["technique_id"] for m in result["mitre_attack_matrix"])
