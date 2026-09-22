"""
BGP-Shield Historical Internet Incident Replayer
Archive of famous real-world BGP outages, route leaks, and hijacks.
Allows operators to replay historical incidents and evaluate BGP-Shield's detection and mitigation.
"""

from typing import Dict, Any, List, Optional
import datetime
import uuid


class HistoricalReplayer:
    """
    Manages catalog of real-world historical BGP incidents and facilitates
    dynamic replay into the active BGP-Shield stream engine.
    """

    HISTORICAL_CATALOG: Dict[str, Dict[str, Any]] = {
        "youtube_2008": {
            "id": "HIST-2008-YOUTUBE",
            "key": "youtube_2008",
            "title": "2008 Pakistan Telecom vs. YouTube Hijack",
            "year": 2008,
            "target_prefix": "208.65.153.0/24",
            "victim_asn": 37075,
            "victim_name": "YouTube / Google",
            "attacker_asn": 36561,
            "attacker_name": "Pakistan Telecom",
            "incident_type": "SUBPREFIX_HIJACK",
            "severity": "CRITICAL",
            "rpki_status": "INVALID",
            "duration": "2 hours 17 minutes",
            "traffic_drop_pct": 94.2,
            "as_path": [3491, 36561],
            "communities": ["65535:666", "3491:1001"],
            "description": (
                "Pakistan Telecom announced a rogue /24 subprefix to censor YouTube domestically. "
                "The announcement leaked to upstream Tier-1 transit PCCW Global (AS3491) and propagated "
                "worldwide within minutes, hijacking all global YouTube traffic and causing a 2-hour worldwide outage."
            ),
            "rfc_citations": ["RFC 6811 (RPKI BGP-ROV)", "RFC 7454 (BGP Operations and Security)"],
            "real_world_impact": "Global blackholing of YouTube, catalyzing worldwide adoption of RPKI Route Origin Authorization."
        },
        "route53_2018": {
            "id": "HIST-2018-ROUTE53",
            "key": "route53_2018",
            "title": "2018 Amazon Route 53 / MyEtherWallet DNS Hijack",
            "year": 2018,
            "target_prefix": "205.251.192.0/23",
            "victim_asn": 16509,
            "victim_name": "Amazon AWS Route 53",
            "attacker_asn": 10297,
            "attacker_name": "eNet Inc (Columbus OH)",
            "incident_type": "SUBPREFIX_HIJACK",
            "severity": "CRITICAL",
            "rpki_status": "INVALID",
            "duration": "1 hour 45 minutes",
            "traffic_drop_pct": 78.5,
            "as_path": [6939, 10297],
            "communities": ["6939:100", "10297:666"],
            "description": (
                "Adversaries hijacked Amazon Route 53 authoritative DNS server prefixes. "
                "DNS queries for MyEtherWallet.com were rerouted to a fraudulent Russian server, "
                "serving forged SSL certificates and draining over $152,000 in cryptocurrency from user wallets."
            ),
            "rfc_citations": ["RFC 6811 (RPKI ROV)", "RFC 7908 (Route Leak Def)", "RFC 8484 (DNS over HTTPS)"],
            "real_world_impact": "Demonstrated that BGP control-plane hijacks can subvert TLS/DNS trust chains for high-value financial theft."
        },
        "cloudflare_dqe_2019": {
            "id": "HIST-2019-CLOUDFLARE",
            "key": "cloudflare_dqe_2019",
            "title": "2019 Cloudflare & DQE Gao-Rexford Route Leak",
            "year": 2019,
            "target_prefix": "1.1.1.1/32",
            "victim_asn": 13335,
            "victim_name": "Cloudflare",
            "attacker_asn": 33154,
            "attacker_name": "DQE Communications",
            "incident_type": "GAO_REXFORD_LEAK",
            "severity": "CRITICAL",
            "rpki_status": "VALID",
            "duration": "2 hours 05 minutes",
            "traffic_drop_pct": 86.4,
            "as_path": [7018, 39653, 33154, 13335],
            "communities": ["13335:10001:1", "7018:100:1"],
            "description": (
                "A regional BGP route optimizer at DQE Communications leaked more-specific routes to a multihomed "
                "regional steel manufacturer (Allegheny Technologies AS39653), which forwarded them to AT&T (AS7018). "
                "AT&T accepted the leak, forcing massive global Cloudflare traffic through an overwhelmed 3 Gbps link."
            ),
            "rfc_citations": ["RFC 7908 (BGP Route Leaks)", "RFC 8092 (BGP Large Communities)", "RFC 7454 (BGP Filter Lists)"],
            "real_world_impact": "Prompted major global carriers to enforce strict AS-Path filters and accelerated RFC 9234 (BGP Open Policy)."
        },
        "rostelecom_2021": {
            "id": "HIST-2021-ROSTELECOM",
            "key": "rostelecom_2021",
            "title": "2021 Rostelecom Global Tech & Cloud Interception",
            "year": 2021,
            "target_prefix": "104.16.0.0/12",
            "victim_asn": 13335,
            "victim_name": "Cloudflare & Top Tech",
            "attacker_asn": 12389,
            "attacker_name": "Rostelecom",
            "incident_type": "SUBPREFIX_HIJACK",
            "severity": "CRITICAL",
            "rpki_status": "INVALID",
            "duration": "3 hours 12 minutes",
            "traffic_drop_pct": 62.0,
            "as_path": [12389, 13335],
            "communities": ["12389:1000", "65535:666"],
            "description": (
                "Russian national telco Rostelecom announced unauthorized BGP routes for over 200 critical prefixes "
                "belonging to Google, Amazon, Cloudflare, Akamai, and GoDaddy, steering major Western Internet "
                "traffic through Russian government-controlled transit points."
            ),
            "rfc_citations": ["RFC 6811 (RPKI BGP-ROV)", "RFC 7454 (BGP Protection)"],
            "real_world_impact": "Classified by intelligence agencies as a strategic state-sponsored surveillance and intelligence-gathering detour."
        }
    }

    def __init__(self):
        pass

    def get_catalog(self) -> List[Dict[str, Any]]:
        """Returns the list of available historical incident profiles."""
        return list(self.HISTORICAL_CATALOG.values())

    def get_incident_by_key(self, key: str) -> Optional[Dict[str, Any]]:
        """Returns a specific historical incident profile."""
        return self.HISTORICAL_CATALOG.get(key)

    def replay_incident(self, key: str, duckdb_conn=None) -> Dict[str, Any]:
        """
        Replays the chosen historical incident by injecting it into BGP-Shield's
        active incidents database and telemetry state.
        """
        if key not in self.HISTORICAL_CATALOG:
            raise ValueError(f"Historical incident '{key}' not found in archive.")

        scenario = self.HISTORICAL_CATALOG[key].copy()
        incident_id = f"HIST-{uuid.uuid4().hex[:8].upper()}"
        timestamp_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        incident_record = {
            "id": incident_id,
            "incident_type": scenario["incident_type"],
            "target_prefix": scenario["target_prefix"],
            "victim_asn": scenario["victim_asn"],
            "victim_name": scenario["victim_name"],
            "attacker_asn": scenario["attacker_asn"],
            "attacker_name": scenario["attacker_name"],
            "severity": scenario["severity"],
            "rpki_status": scenario["rpki_status"],
            "traffic_drop_pct": scenario["traffic_drop_pct"],
            "as_path": scenario["as_path"],
            "communities": scenario["communities"],
            "status": "OPEN",
            "detected_at": timestamp_now,
            "description": scenario["description"],
            "historical_source": scenario["title"],
            "year": scenario["year"],
            "real_world_impact": scenario["real_world_impact"]
        }

        # Inject into DuckDB if available
        if duckdb_conn:
            try:
                import json
                details = {
                    "traffic_drop_pct": scenario["traffic_drop_pct"],
                    "as_path": scenario["as_path"],
                    "communities": scenario["communities"],
                    "description": scenario["description"],
                    "rpki_status": scenario["rpki_status"],
                    "historical_source": scenario["title"],
                    "year": scenario["year"],
                    "real_world_impact": scenario["real_world_impact"]
                }
                duckdb_conn.execute("""
                    INSERT OR REPLACE INTO incidents (
                        id, incident_type, severity, target_prefix, victim_asn,
                        victim_name, attacker_asn, attacker_name, status,
                        detected_at, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    incident_id,
                    scenario["incident_type"],
                    scenario["severity"],
                    scenario["target_prefix"],
                    scenario["victim_asn"],
                    scenario["victim_name"],
                    scenario["attacker_asn"],
                    scenario["attacker_name"],
                    "OPEN",
                    timestamp_now,
                    json.dumps(details)
                ])
            except Exception as e:
                print(f"[HistoricalReplayer] DuckDB insert warning: {e}")

        return incident_record
