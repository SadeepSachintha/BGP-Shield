"""
BGP-Shield DuckDB Database Manager
Handles columnar storage, fast batch inserts, and sub-second analytical queries
for BGP routing updates, NetFlow telemetry, and security incidents.
"""
import duckdb
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import threading
from config import DUCKDB_PATH, TIER1_ASNS, NOTABLE_ASNS

logger = logging.getLogger("bgp_shield.db")

class DuckDBManager:
    def __init__(self, db_path: str = DUCKDB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._con = duckdb.connect(self.db_path)
        self._init_db()

    def _get_connection(self):
        return self._con

    def _init_db(self):
        """Initialize DuckDB tables and views."""
        with self._lock:
            con = self._get_connection()
            con.execute("""
                CREATE TABLE IF NOT EXISTS bgp_events (
                    id VARCHAR PRIMARY KEY,
                    timestamp TIMESTAMP,
                    event_type VARCHAR,
                    peer_ip VARCHAR,
                    peer_asn BIGINT,
                    prefix VARCHAR,
                    origin_asn BIGINT,
                    as_path VARCHAR,
                    path_length INTEGER,
                    rpki_status VARCHAR,
                    is_leak BOOLEAN,
                    leak_type VARCHAR,
                    is_hijack BOOLEAN,
                    hijack_type VARCHAR,
                    severity VARCHAR,
                    raw_json VARCHAR
                );
            """)

            con.execute("""
                CREATE TABLE IF NOT EXISTS netflow_records (
                    id VARCHAR PRIMARY KEY,
                    timestamp TIMESTAMP,
                    src_ip VARCHAR,
                    dst_ip VARCHAR,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol VARCHAR,
                    bytes BIGINT,
                    packets BIGINT,
                    amplification_factor DOUBLE,
                    is_ddos_vector BOOLEAN,
                    vector_type VARCHAR
                );
            """)

            con.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id VARCHAR PRIMARY KEY,
                    incident_type VARCHAR,
                    severity VARCHAR,
                    target_prefix VARCHAR,
                    victim_asn BIGINT,
                    victim_name VARCHAR,
                    attacker_asn BIGINT,
                    attacker_name VARCHAR,
                    status VARCHAR,
                    detected_at TIMESTAMP,
                    resolved_at TIMESTAMP,
                    details_json VARCHAR
                );
            """)

            con.execute("""
                CREATE TABLE IF NOT EXISTS as_nodes (
                    asn BIGINT PRIMARY KEY,
                    name VARCHAR,
                    tier VARCHAR,
                    country VARCHAR,
                    last_seen TIMESTAMP
                );
            """)

            con.execute("""
                CREATE TABLE IF NOT EXISTS as_links (
                    source_asn BIGINT,
                    target_asn BIGINT,
                    relationship VARCHAR,
                    last_seen TIMESTAMP,
                    PRIMARY KEY (source_asn, target_asn)
                );
            """)

            # Pre-populate known ASNs
            for asn, name in TIER1_ASNS.items():
                con.execute("""
                    INSERT OR REPLACE INTO as_nodes (asn, name, tier, country, last_seen)
                    VALUES (?, ?, 'Tier-1 Backbone', 'Global', CURRENT_TIMESTAMP);
                """, [asn, name])

            for asn, info in NOTABLE_ASNS.items():
                con.execute("""
                    INSERT OR REPLACE INTO as_nodes (asn, name, tier, country, last_seen)
                    VALUES (?, ?, ?, 'Global', CURRENT_TIMESTAMP);
                """, [asn, info["name"], info["tier"]])

    def insert_bgp_event(self, event: Dict[str, Any]):
        """Insert a single BGP event record."""
        with self._lock:
            con = self._get_connection()
            con.execute("""
                INSERT OR REPLACE INTO bgp_events (
                    id, timestamp, event_type, peer_ip, peer_asn, prefix,
                    origin_asn, as_path, path_length, rpki_status,
                    is_leak, leak_type, is_hijack, hijack_type, severity, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, [
                event.get("id"),
                event.get("timestamp", datetime.now(timezone.utc)),
                event.get("event_type", "ANNOUNCE"),
                event.get("peer_ip", ""),
                event.get("peer_asn", 0),
                event.get("prefix", ""),
                event.get("origin_asn", 0),
                json.dumps(event.get("as_path", []), default=str),
                event.get("path_length", 0),
                event.get("rpki_status", "UNKNOWN"),
                event.get("is_leak", False),
                event.get("leak_type", "NONE"),
                event.get("is_hijack", False),
                event.get("hijack_type", "NONE"),
                event.get("severity", "INFO"),
                json.dumps(event, default=str)
            ])

    def insert_netflow_record(self, record: Dict[str, Any]):
        """Insert a NetFlow telemetry record."""
        with self._lock:
            con = self._get_connection()
            con.execute("""
                INSERT OR REPLACE INTO netflow_records (
                    id, timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, bytes, packets, amplification_factor,
                    is_ddos_vector, vector_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, [
                record.get("id"),
                record.get("timestamp", datetime.now(timezone.utc)),
                record.get("src_ip", ""),
                record.get("dst_ip", ""),
                record.get("src_port", 0),
                record.get("dst_port", 0),
                record.get("protocol", "TCP"),
                record.get("bytes", 0),
                record.get("packets", 0),
                record.get("amplification_factor", 1.0),
                record.get("is_ddos_vector", False),
                record.get("vector_type", "NONE")
            ])

    def record_incident(self, incident: Dict[str, Any]):
        """Record or update a security incident."""
        with self._lock:
            con = self._get_connection()
            con.execute("""
                INSERT OR REPLACE INTO incidents (
                    id, incident_type, severity, target_prefix, victim_asn,
                    victim_name, attacker_asn, attacker_name, status,
                    detected_at, resolved_at, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, [
                incident.get("id"),
                incident.get("incident_type"),
                incident.get("severity", "HIGH"),
                incident.get("target_prefix", ""),
                incident.get("victim_asn", 0),
                incident.get("victim_name", "Unknown"),
                incident.get("attacker_asn", 0),
                incident.get("attacker_name", "Unknown"),
                incident.get("status", "DETECTED"),
                incident.get("detected_at", datetime.now(timezone.utc)),
                incident.get("resolved_at"),
                json.dumps(incident, default=str)
            ])

    def record_as_link(self, src_asn: int, dst_asn: int, relationship: str = "PEER"):
        """Record an observed AS link in the topology."""
        with self._lock:
            con = self._get_connection()
            con.execute("""
                INSERT OR REPLACE INTO as_links (source_asn, target_asn, relationship, last_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP);
            """, [src_asn, dst_asn, relationship])

    def get_recent_bgp_events(self, limit: int = 50, filter_threats_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieve recent BGP events with optional threat filtering."""
        query = """
            SELECT id, timestamp, event_type, peer_ip, peer_asn, prefix,
                   origin_asn, as_path, path_length, rpki_status,
                   is_leak, leak_type, is_hijack, hijack_type, severity
            FROM bgp_events
        """
        if filter_threats_only:
            query += " WHERE is_hijack = TRUE OR is_leak = TRUE OR severity IN ('HIGH', 'CRITICAL')"
        query += " ORDER BY timestamp DESC LIMIT ?;"

        with self._lock:
            con = self._get_connection()
            results = con.execute(query, [limit]).fetchall()
            columns = [desc[0] for desc in con.description]
            events = []
            for row in results:
                d = dict(zip(columns, row))
                if isinstance(d.get("as_path"), str):
                    try:
                        d["as_path"] = json.loads(d["as_path"])
                    except Exception:
                        pass
                if isinstance(d.get("timestamp"), datetime):
                    d["timestamp"] = d["timestamp"].isoformat()
                events.append(d)
            return events

    def get_active_incidents(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get list of active or recent security incidents."""
        with self._lock:
            con = self._get_connection()
            results = con.execute("""
                SELECT id, incident_type, severity, target_prefix, victim_asn,
                       victim_name, attacker_asn, attacker_name, status,
                       detected_at, resolved_at, details_json
                FROM incidents
                ORDER BY detected_at DESC LIMIT ?;
            """, [limit]).fetchall()
            columns = [desc[0] for desc in con.description]
            incidents = []
            for row in results:
                d = dict(zip(columns, row))
                if isinstance(d.get("detected_at"), datetime):
                    d["detected_at"] = d["detected_at"].isoformat()
                if isinstance(d.get("resolved_at"), datetime):
                    d["resolved_at"] = d["resolved_at"].isoformat()
                if isinstance(d.get("details_json"), str):
                    try:
                        d["details"] = json.loads(d["details_json"])
                    except Exception:
                        d["details"] = {}
                incidents.append(d)
            return incidents

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        with self._lock:
            con = self._get_connection()
            results = con.execute("""
                SELECT id, incident_type, severity, target_prefix, victim_asn,
                       victim_name, attacker_asn, attacker_name, status,
                       detected_at, resolved_at, details_json
                FROM incidents
                WHERE id = ?;
            """, [incident_id]).fetchall()
            if not results:
                return None
            columns = [desc[0] for desc in con.description]
            d = dict(zip(columns, results[0]))
            if isinstance(d.get("detected_at"), datetime):
                d["detected_at"] = d["detected_at"].isoformat()
            if isinstance(d.get("resolved_at"), datetime):
                d["resolved_at"] = d["resolved_at"].isoformat()
            if isinstance(d.get("details_json"), str):
                try:
                    d["details"] = json.loads(d["details_json"])
                except Exception:
                    d["details"] = {}
            return d

    def get_netflow_analytics(self) -> Dict[str, Any]:
        """Aggregate NetFlow telemetry metrics."""
        with self._lock:
            con = self._get_connection()
            stats = con.execute("""
                SELECT 
                    COALESCE(SUM(bytes), 0) as total_bytes,
                    COALESCE(SUM(packets), 0) as total_packets,
                    COALESCE(COUNT(CASE WHEN is_ddos_vector = TRUE THEN 1 END), 0) as ddos_events,
                    COALESCE(MAX(amplification_factor), 1.0) as peak_amplification
                FROM netflow_records;
            """).fetchone()

            proto_breakdown = con.execute("""
                SELECT vector_type, COUNT(*) as count, SUM(bytes) as total_bytes
                FROM netflow_records
                WHERE is_ddos_vector = TRUE
                GROUP BY vector_type;
            """).fetchall()

            return {
                "total_bytes": stats[0],
                "total_packets": stats[1],
                "ddos_events": stats[2],
                "peak_amplification": stats[3],
                "protocols": [
                    {"vector": r[0], "count": r[1], "bytes": r[2]} for r in proto_breakdown
                ]
            }

    def get_topology(self) -> Dict[str, Any]:
        """Return nodes and links for D3 force-directed graph."""
        with self._lock:
            con = self._get_connection()
            nodes_raw = con.execute("SELECT asn, name, tier, country FROM as_nodes;").fetchall()
            links_raw = con.execute("SELECT source_asn, target_asn, relationship FROM as_links;").fetchall()

            nodes = [
                {"id": f"AS{r[0]}", "asn": r[0], "name": r[1], "tier": r[2], "country": r[3]}
                for r in nodes_raw
            ]
            links = [
                {"source": f"AS{r[0]}", "target": f"AS{r[1]}", "type": r[2]}
                for r in links_raw
            ]

            return {"nodes": nodes, "links": links}
