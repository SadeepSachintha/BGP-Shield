"""
BGP-Shield Engine Configuration
Settings for RIPE RIS live stream, DuckDB columnar database, and detection parameters.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database
DUCKDB_PATH = str(DATA_DIR / "bgp_shield.duckdb")

# External Feeds
RIPE_RIS_WS_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgp-shield-sentinel"
RIPE_RIS_CLIENT_ID = "bgp-shield-sentinel"

# API Bridge Server
API_HOST = "127.0.0.1"
API_PORT = 8000

# Detection Thresholds
MAX_NORMAL_AS_PATH_LENGTH = 7
MAX_ALLOWED_PREPEND_COUNT = 4
LEAK_DETECTION_WINDOW_SECONDS = 60
FLOW_DROP_HIJACK_THRESHOLD_PERCENT = 65.0

# Pre-seeded Tier-1 ASNs (Global Transit Backbones)
TIER1_ASNS = {
    174: "Cogent Communications",
    3356: "Lumen Technologies (Level 3)",
    1299: "Arelion (Telia Carrier)",
    2914: "NTT Communications",
    7018: "AT&T",
    6453: "Tata Communications",
    6762: "Sparkle (Telecom Italia)",
    3257: "GTT Communications",
    6830: "Liberty Global",
    3491: "PCCW Global",
    1239: "Sprint / T-Mobile",
    6461: "Zayo Group",
    5511: "Orange S.A.",
}

# Pre-seeded Major ASNs
NOTABLE_ASNS = {
    15169: {"name": "Google LLC", "type": "Cloud / Content", "tier": "Tier-1 Peer"},
    16509: {"name": "Amazon Web Services (AWS)", "type": "Cloud / Hosting", "tier": "Tier-1 Peer"},
    13335: {"name": "Cloudflare, Inc.", "type": "CDN / Security", "tier": "Tier-1 Peer"},
    8075: {"name": "Microsoft Corporation", "type": "Cloud / Content", "tier": "Tier-1 Peer"},
    20940: {"name": "Akamai Technologies", "type": "CDN", "tier": "Content"},
    36692: {"name": "Cisco OpenDNS LLC", "type": "DNS / Security", "tier": "Content"},
    19281: {"name": "Quad9 DNS", "type": "DNS / Security", "tier": "Content"},
    4761: {"name": "Indosat Ooredoo", "type": "Transit / ISP", "tier": "Tier-2"},
    37282: {"name": "MainOne Cable Company", "type": "Transit / ISP", "tier": "Tier-2"},
    9002: {"name": "RETN", "type": "Transit / Backbone", "tier": "Tier-2"},
}

# Pre-seeded RPKI ROA Records (Prefix -> Authorized ASN & MaxLength)
DEFAULT_ROA_DATABASE = {
    "8.8.8.0/24": {"asn": 15169, "max_length": 24, "holder": "Google DNS"},
    "8.8.4.0/24": {"asn": 15169, "max_length": 24, "holder": "Google DNS"},
    "1.1.1.0/24": {"asn": 13335, "max_length": 24, "holder": "Cloudflare DNS"},
    "1.0.0.0/24": {"asn": 13335, "max_length": 24, "holder": "Cloudflare DNS"},
    "208.67.222.0/24": {"asn": 36692, "max_length": 24, "holder": "Cisco OpenDNS"},
    "208.67.220.0/24": {"asn": 36692, "max_length": 24, "holder": "Cisco OpenDNS"},
    "9.9.9.0/24": {"asn": 19281, "max_length": 24, "holder": "Quad9 DNS"},
    "13.32.0.0/15": {"asn": 16509, "max_length": 16, "holder": "Amazon CloudFront"},
    "54.239.0.0/16": {"asn": 16509, "max_length": 24, "holder": "Amazon AWS"},
    "104.16.0.0/12": {"asn": 13335, "max_length": 20, "holder": "Cloudflare Edge"},
}

# Known AS Relationships: 'C2P' (Customer to Provider), 'P2P' (Peer to Peer), 'P2C' (Provider to Customer)
# Tuple: (ASN_A, ASN_B) -> relationship of A towards B
DEFAULT_AS_RELATIONSHIPS = {
    # Stub / Content Customers to Tier-1 Providers
    (15169, 174): "C2P",
    (15169, 3356): "C2P",
    (15169, 1299): "C2P",
    (16509, 3356): "C2P",
    (16509, 2914): "C2P",
    (13335, 174): "C2P",
    (13335, 3356): "C2P",
    (36692, 3356): "C2P",
    (19281, 1299): "C2P",
    (4761, 3356): "C2P",
    (37282, 3356): "C2P",
    (37282, 174): "C2P",

    # Reverse Provider to Customer
    (174, 15169): "P2C",
    (3356, 15169): "P2C",
    (1299, 15169): "P2C",
    (3356, 16509): "P2C",
    (2914, 16509): "P2C",
    (174, 13335): "P2C",
    (3356, 13335): "P2C",
    (3356, 36692): "P2C",
    (1299, 19281): "P2C",
    (3356, 4761): "P2C",
    (3356, 37282): "P2C",
    (174, 37282): "P2C",

    # Tier-1 Peering (P2P)
    (174, 3356): "P2P",
    (3356, 174): "P2P",
    (174, 1299): "P2P",
    (1299, 174): "P2P",
    (3356, 1299): "P2P",
    (1299, 3356): "P2P",
    (3356, 2914): "P2P",
    (2914, 3356): "P2P",
    (174, 2914): "P2P",
    (2914, 174): "P2P",
    (7018, 3356): "P2P",
    (3356, 7018): "P2P",
}
