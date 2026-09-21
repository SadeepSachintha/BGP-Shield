import pytest
import sys
from pathlib import Path

# Add engine directory to path
current_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(current_dir))

import asyncio
from peeringdb_client import PeeringDbClient

def test_peeringdb_preseeded():
    client = PeeringDbClient()

    # Test Cogent AS174
    cogent = asyncio.run(client.get_asn_metadata(174))
    assert cogent["asn"] == 174
    assert "Cogent" in cogent["name"]
    assert cogent["policy_general"] == "Open"
    assert cogent["fac_count"] >= 400
    assert len(cogent["ixp_presences"]) >= 3

    # Test Cloudflare AS13335
    cf = asyncio.run(client.get_asn_metadata(13335))
    assert cf["asn"] == 13335
    assert "Cloudflare" in cf["name"]
    assert cf["policy_general"] == "Open"
    assert "1 Tbps+" in cf["public_peering_capacity"]

def test_peeringdb_fallback():
    client = PeeringDbClient()
    unknown = asyncio.run(client.get_asn_metadata(999999))
    assert unknown["asn"] == 999999
    assert unknown["source"] in ["PeeringDB Live API", "Heuristic Fallback"]

