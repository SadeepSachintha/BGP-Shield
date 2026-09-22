"""
Unit tests for BGP-Shield Historical Internet Incident Replayer.
"""

import pytest
import sys
import os

# Add engine directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from historical_replayer import HistoricalReplayer


def test_catalog_retrieval():
    replayer = HistoricalReplayer()
    catalog = replayer.get_catalog()

    assert len(catalog) >= 4
    keys = [item["key"] for item in catalog]
    assert "youtube_2008" in keys
    assert "route53_2018" in keys
    assert "cloudflare_dqe_2019" in keys
    assert "rostelecom_2021" in keys


def test_replay_incident_generation():
    replayer = HistoricalReplayer()
    record = replayer.replay_incident("youtube_2008")

    assert record["id"].startswith("HIST-")
    assert record["target_prefix"] == "208.65.153.0/24"
    assert record["victim_asn"] == 37075
    assert record["attacker_asn"] == 36561
    assert record["incident_type"] == "SUBPREFIX_HIJACK"
    assert record["status"] == "OPEN"
    assert "Pakistan Telecom" in record["attacker_name"]


def test_replay_unknown_incident_raises_error():
    replayer = HistoricalReplayer()
    with pytest.raises(ValueError, match="not found in archive"):
        replayer.replay_incident("non_existent_2099")
