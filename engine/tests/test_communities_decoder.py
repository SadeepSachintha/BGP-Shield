import pytest
import sys
from pathlib import Path

# Add engine directory to path
current_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(current_dir))

from bgp_communities_decoder import BgpCommunitiesDecoder

def test_decode_standard_well_known():
    # Test RFC 1997 NO_EXPORT
    no_export = BgpCommunitiesDecoder.decode_community("65535:65281")
    assert no_export["type"] == "STANDARD_RFC1997"
    assert no_export["action"] == "NO_EXPORT"
    assert no_export["category"] == "ACTION_NO_EXPORT"

    # Test RFC 7999 BLACKHOLE
    blackhole = BgpCommunitiesDecoder.decode_community("65535:666")
    assert blackhole["type"] == "STANDARD_RFC1997"
    assert blackhole["action"] == "BLACKHOLE"
    assert blackhole["category"] == "ACTION_BLACKHOLE"

def test_decode_large_communities_tier1():
    # Test Cogent Do Not Export
    cogent_no_export = BgpCommunitiesDecoder.decode_community("174:999:0")
    assert cogent_no_export["type"] == "LARGE_RFC8092"
    assert cogent_no_export["asn"] == 174
    assert cogent_no_export["action"] == "Do Not Export to Tier-1 Peers"
    assert cogent_no_export["category"] == "ACTION_NO_EXPORT"

    # Test Lumen Local-Pref
    lumen_lp = BgpCommunitiesDecoder.decode_community("3356:100:1")
    assert lumen_lp["type"] == "LARGE_RFC8092"
    assert lumen_lp["asn"] == 3356
    assert "Set Local Preference" in lumen_lp["action"]

    # Test Cloudflare PoP
    cf_na = BgpCommunitiesDecoder.decode_community("13335:10001:1")
    assert cf_na["type"] == "LARGE_RFC8092"
    assert cf_na["asn"] == 13335
    assert "North America" in cf_na["action"]

def test_analyze_route_communities():
    comm_list = ["65535:666", "174:999:0", "13335:10001:1"]
    analysis = BgpCommunitiesDecoder.analyze_route_communities(comm_list)
    assert analysis["total_communities"] == 3
    assert analysis["has_blackhole"] is True
    assert analysis["has_no_export"] is True
    assert analysis["has_geo_tag"] is True
    assert "CRITICAL" in analysis["security_alert"]
