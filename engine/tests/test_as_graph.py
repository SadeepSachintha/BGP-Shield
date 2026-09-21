"""
Unit tests for ASGraphAnalyzer: Gao-Rexford Valley-Free and Sub-prefix Hijack algorithms.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from as_graph_analyzer import ASGraphAnalyzer

@pytest.fixture
def analyzer():
    return ASGraphAnalyzer()

def test_rpki_valid(analyzer):
    status, roa = analyzer.validate_rpki("8.8.8.0/24", 15169)
    assert status == "VALID"
    assert roa["holder"] == "Google DNS"

def test_rpki_invalid_origin(analyzer):
    # Rogue AS announces Google DNS
    status, roa = analyzer.validate_rpki("8.8.8.0/24", 4761)
    assert status == "INVALID_ASN"
    assert roa["asn"] == 15169

def test_subprefix_hijack(analyzer):
    # Attacker announces /25 of OpenDNS /24
    hijack = analyzer.check_subprefix_hijack("208.67.222.0/25", 4761)
    assert hijack is not None
    assert hijack["type"] == "SUBPREFIX_HIJACK"
    assert hijack["legitimate_asn"] == 36692
    assert hijack["rogue_asn"] == 4761
    assert hijack["severity"] == "CRITICAL"

def test_exact_prefix_hijack(analyzer):
    hijack = analyzer.check_subprefix_hijack("1.1.1.0/24", 99999)
    assert hijack is not None
    assert hijack["type"] == "EXACT_PREFIX_HIJACK"
    assert hijack["legitimate_asn"] == 13335

def test_gao_rexford_valley_free_leak(analyzer):
    # Path: Cogent(174) -> MainOne(37282) -> Lumen(3356) -> Cloudflare(13335)
    # 174 -> 37282 is P2C
    # 37282 -> 3356 is C2P (Customer to Provider) after Downhill -> Valley-Free Violation!
    as_path = [174, 37282, 3356, 13335]
    leak = analyzer.check_valley_free_route_leak(as_path)
    assert leak is not None
    assert leak["type"] == "ROUTE_LEAK_VALLEY_FREE"
    assert leak["leak_as"] == 37282

def test_valid_as_path(analyzer):
    # Valid customer-to-provider path: Cloudflare(13335) -> Lumen(3356) -> Cogent(174)
    as_path = [174, 3356, 13335]
    leak = analyzer.check_valley_free_route_leak(as_path)
    assert leak is None
