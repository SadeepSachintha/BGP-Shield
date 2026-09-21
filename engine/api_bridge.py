"""
BGP-Shield API Bridge & Real-Time Telemetry Hub
FastAPI server providing WebSocket/SSE streams, REST endpoints for DuckDB queries,
attack simulations, and mitigation playbook generators.
"""
import asyncio
import json
import logging
from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from config import API_HOST, API_PORT
from db_manager import DuckDBManager
from as_graph_analyzer import ASGraphAnalyzer
from netflow_correlator import NetFlowCorrelator
from simulator import AttackSimulator
from ripe_ris_consumer import RipeRisConsumer
from rpki_live_sync import RpkiLiveSync
from netflow_udp_collector import start_netflow_udp_server, NetFlowV9Parser
from postmortem_generator import PostMortemGenerator
import socket

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("bgp_shield.api")

app = FastAPI(
    title="BGP-Shield Sentinel API",
    description="Cyber Threat Intelligence & BGP Route Leak Sentinel Engine",
    version="1.0.0"
)

# Enable CORS for React frontend & Laravel gateway
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core singletons
db_manager = DuckDBManager()
analyzer = ASGraphAnalyzer()
netflow_correlator = NetFlowCorrelator()
simulator = AttackSimulator(analyzer, netflow_correlator, db_manager)
rpki_sync = RpkiLiveSync(analyzer)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead_conns = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead_conns.append(conn)
        for dead in dead_conns:
            self.disconnect(dead)

ws_manager = ConnectionManager()

# Background consumer instances
ris_consumer: Optional[RipeRisConsumer] = None
consumer_task: Optional[asyncio.Task] = None
udp_transport = None

async def broadcast_event(event: dict):
    await ws_manager.broadcast(event)

@app.on_event("startup")
async def startup_event():
    global ris_consumer, consumer_task, udp_transport
    # Pre-seed initial sample topology links
    db_manager.record_as_link(174, 3356, "P2P")
    db_manager.record_as_link(3356, 1299, "P2P")
    db_manager.record_as_link(174, 15169, "P2C")
    db_manager.record_as_link(3356, 16509, "P2C")
    db_manager.record_as_link(1299, 13335, "P2C")
    db_manager.record_as_link(3356, 36692, "P2C")

    # Start RIPE RIS live consumer in background
    ris_consumer = RipeRisConsumer(analyzer, db_manager, on_event_callback=broadcast_event)
    consumer_task = asyncio.create_task(ris_consumer.start())

    # Start Native NetFlow UDP Collector on port 2055
    udp_transport, _ = await start_netflow_udp_server(netflow_correlator, db_manager, port=2055)

    # Trigger background live RPKI ROA sync from Cloudflare
    asyncio.create_task(rpki_sync.sync_from_cloudflare(max_roas=25000))
    logger.info("BGP-Shield Engine & UDP NetFlow Collector initialized.")

@app.on_event("shutdown")
async def shutdown_event():
    global ris_consumer, consumer_task, udp_transport
    if ris_consumer:
        ris_consumer.stop()
    if consumer_task:
        consumer_task.cancel()
    if udp_transport:
        udp_transport.close()

# --- Endpoints ---

@app.get("/api/status")
async def get_status():
    """Return engine health and ingestion metrics."""
    return {
        "status": "ONLINE",
        "live_feed_connected": ris_consumer.connected if ris_consumer else False,
        "messages_processed": ris_consumer.messages_processed if ris_consumer else 0,
        "threats_detected": ris_consumer.threats_detected if ris_consumer else 0,
        "ws_clients": len(ws_manager.active_connections),
        "db_type": "DuckDB Columnar Store"
    }

@app.get("/api/events")
async def get_events(limit: int = Query(50, ge=1, le=500), threats_only: bool = Query(False)):
    """Fetch recent BGP events from DuckDB."""
    return await asyncio.to_thread(db_manager.get_recent_bgp_events, limit=limit, filter_threats_only=threats_only)

@app.get("/api/incidents")
async def get_incidents(limit: int = Query(20, ge=1, le=100)):
    """Fetch active security incidents."""
    return await asyncio.to_thread(db_manager.get_active_incidents, limit=limit)

@app.get("/api/topology")
async def get_topology():
    """Fetch graph nodes and links for D3 force-directed visualization."""
    return await asyncio.to_thread(db_manager.get_topology)

@app.get("/api/netflow")
async def get_netflow():
    """Fetch NetFlow analytics and DDoS vector breakdown."""
    correlator_summary = netflow_correlator.get_summary_telemetry()
    db_analytics = await asyncio.to_thread(db_manager.get_netflow_analytics)
    return {
        "telemetry": correlator_summary,
        "analytics": db_analytics
    }

@app.post("/api/simulate/{scenario}")
async def trigger_simulation(scenario: str):
    """
    Trigger realistic chaos/attack simulations:
    - subprefix_hijack
    - route_leak
    - ddos_amplification
    """
    if scenario == "subprefix_hijack":
        result = simulator.simulate_subprefix_hijack()
    elif scenario == "route_leak":
        result = simulator.simulate_route_leak()
    elif scenario == "ddos_amplification":
        result = simulator.simulate_ddos_amplification()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown simulation scenario '{scenario}'")

    # Broadcast to connected WebSocket clients immediately
    if "bgp_event" in result:
        await ws_manager.broadcast(result["bgp_event"])
    elif "incident" in result:
        await ws_manager.broadcast({
            "type": "INCIDENT_ALERT",
            "incident": result["incident"]
        })

    return {"status": "SUCCESS", "scenario": scenario, "result": result}

@app.post("/api/mitigate")
def generate_mitigation(prefix: str, rogue_asn: int, incident_type: str = "SUBPREFIX_HIJACK"):
    """
    Generate executable router configurations and BGP Flowspec rules for mitigation.
    Supported targets: Cisco IOS-XR, Juniper Junos, BIRD, FRRouting, and BGP Flowspec (RFC 5575).
    """
    # 1. BGP Flowspec (RFC 5575)
    flowspec_junos = f"""# Juniper Junos BGP Flowspec Filter
set firewall family inet flow route drop-rogue-flow match destination {prefix}
set firewall family inet flow route drop-rogue-flow then discard
commit comment "BGP-Shield Automated Mitigation for {prefix}"
"""
    flowspec_cisco = f"""! Cisco IOS-XR BGP Flowspec Policy
flowspec
 local-install interface all
 address-family ipv4
  class-map type traffic match-all CM-DROP-ROGUE
   match destination-address {prefix}
  !
  policy-map type traffic PM-BGP-SHIELD-DROP
   class CM-DROP-ROGUE
    drop
  !
!
"""

    # 2. Remotely Triggered Black Hole (RTBH)
    rtbh_bird = f"""# BIRD Routing Daemon RTBH Trigger
filter rtbh_mitigation {{
    if net = {prefix} then {{
        bgp_community.add((65535, 666)); # Blackhole Community (RFC 7999)
        dest = RTD_BLACKHOLE;
        accept;
    }}
}}
"""

    # 3. Upstream Filter Rule (Filter rogue ASN announcement)
    cisco_as_filter = f"""! Cisco IOS-XR AS-Path Filter
as-path-set ROGUE-ASN-{rogue_asn}
  ios-regex '_{rogue_asn}$'
end-set
!
route-policy DROP-ROGUE-ORIGIN
  if as-path in ROGUE-ASN-{rogue_asn} then
    drop
  endif
end-policy
"""

    return {
        "prefix": prefix,
        "rogue_asn": rogue_asn,
        "incident_type": incident_type,
        "playbooks": {
            "flowspec_junos": flowspec_junos,
            "flowspec_cisco": flowspec_cisco,
            "rtbh_bird": rtbh_bird,
            "cisco_as_filter": cisco_as_filter
        }
    }

@app.get("/api/rpki/status")
async def get_rpki_status():
    """Return live RPKI ROA sync status."""
    return {
        "status": "SYNCED" if rpki_sync.total_roas_loaded > 0 else "INITIALIZING",
        "total_roas": rpki_sync.total_roas_loaded,
        "unique_asns": rpki_sync.unique_asns,
        "last_sync": rpki_sync.last_sync_time,
        "source": "Cloudflare Public RPKI Cache"
    }

@app.post("/api/rpki/sync")
async def trigger_rpki_sync():
    """Trigger on-demand RPKI ROA synchronization."""
    return await rpki_sync.sync_from_cloudflare(max_roas=30000)

@app.get("/api/time-travel/snapshots")
async def get_time_travel_snapshots(incident_id: Optional[str] = None):
    """Return historical time-travel progression steps for incident forensic replayer."""
    return {
        "incident_id": incident_id or "demo-subprefix-hijack",
        "target_prefix": "208.67.222.0/25",
        "legitimate_holder": "Cisco OpenDNS (AS36692)",
        "rogue_asn": 4761,
        "steps": [
            {
                "step": 1,
                "title": "Normal Baseline State",
                "time_offset": "T - 5m",
                "description": "Legitimate /24 announced by AS36692 via Tier-1 transit AS3356. RPKI ROA: VALID. Inbound flow: 1.2 Gbps.",
                "active_path": [174, 3356, 36692],
                "traffic_volume_gbps": 1.2,
                "rpki_state": "VALID",
                "alert_level": "NORMAL",
                "threat_node": None
            },
            {
                "step": 2,
                "title": "Rogue Announcement Injected",
                "time_offset": "T + 0s",
                "description": "Rogue AS4761 announces unauthorized sub-prefix 208.67.222.0/25. RPKI origin mismatch detected!",
                "active_path": [4761],
                "traffic_volume_gbps": 1.2,
                "rpki_state": "INVALID_ASN",
                "alert_level": "WARNING",
                "threat_node": 4761
            },
            {
                "step": 3,
                "title": "Transit Propagation (LPM Divert)",
                "time_offset": "T + 12s",
                "description": "Tier-1 carriers (AS174, AS3356) accept and propagate /25 due to Longest Prefix Match rule.",
                "active_path": [174, 3356, 4761],
                "traffic_volume_gbps": 0.35,
                "rpki_state": "INVALID_ASN",
                "alert_level": "CRITICAL",
                "threat_node": 4761
            },
            {
                "step": 4,
                "title": "Traffic Diversion Collapse",
                "time_offset": "T + 35s",
                "description": "71% inbound DNS traffic collapse on legitimate AS36692. Traffic redirected to rogue origin AS4761.",
                "active_path": [174, 3356, 4761],
                "traffic_volume_gbps": 0.12,
                "rpki_state": "INVALID_ASN",
                "alert_level": "CRITICAL",
                "threat_node": 4761
            },
            {
                "step": 5,
                "title": "Automated Mitigation Deployed",
                "time_offset": "T + 48s",
                "description": "BGP Flowspec discard filter deployed at border routers. Covering /25 announced. Traffic restored.",
                "active_path": [174, 3356, 36692],
                "traffic_volume_gbps": 1.18,
                "rpki_state": "VALID",
                "alert_level": "RESOLVED",
                "threat_node": None
            }
        ]
    }

@app.post("/api/netflow/inject-test-flows")
async def inject_test_netflow_packets(count: int = 3):
    """Inject sample NetFlow v9 UDP datagrams to port 2055 for live telemetry testing."""
    sample_flows = [
        {"src_ip": "198.51.100.10", "dst_ip": "8.8.8.8", "src_port": 11211, "dst_port": 45123, "protocol": "UDP", "bytes": 85000000, "packets": 450000},
        {"src_ip": "203.0.113.5", "dst_ip": "1.1.1.1", "src_port": 123, "dst_port": 51234, "protocol": "UDP", "bytes": 45000000, "packets": 250000},
        {"src_ip": "192.0.2.1", "dst_ip": "208.67.222.1", "src_port": 53, "dst_port": 34123, "protocol": "UDP", "bytes": 12000000, "packets": 120000}
    ]
    packet_data = NetFlowV9Parser.build_test_packet(sample_flows[:count])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(packet_data, ("127.0.0.1", 2055))
        return {
            "status": "SUCCESS",
            "message": f"Sent NetFlow v9 UDP datagram ({len(packet_data)} bytes) with {len(sample_flows[:count])} flow records to 127.0.0.1:2055"
        }
    finally:
        sock.close()

@app.get("/api/incidents/{incident_id}/postmortem")
def get_incident_postmortem(
    incident_id: str,
    prefix: str = Query("208.67.222.0/24"),
    hijacked_subprefix: str = Query("208.67.222.0/25"),
    rogue_asn: int = Query(4761),
    incident_type: str = Query("SUBPREFIX_HIJACK")
):
    """Generate comprehensive structured Post-Mortem data with Markdown & HTML."""
    data = PostMortemGenerator.generate_report_data(
        incident_id=incident_id,
        prefix=prefix,
        hijacked_subprefix=hijacked_subprefix,
        rogue_asn=rogue_asn,
        incident_type=incident_type
    )
    return {
        "data": data,
        "markdown": PostMortemGenerator.to_markdown(data),
        "html": PostMortemGenerator.to_html(data)
    }

@app.get("/api/incidents/{incident_id}/postmortem/download")
def download_incident_postmortem(
    incident_id: str,
    format: str = Query("markdown"),
    prefix: str = Query("208.67.222.0/24")
):
    """Download post-mortem report as .md or .html."""
    from fastapi.responses import Response
    data = PostMortemGenerator.generate_report_data(incident_id=incident_id, prefix=prefix)
    if format == "html":
        content = PostMortemGenerator.to_html(data)
        media_type = "text/html"
        filename = f"postmortem-{incident_id}.html"
    else:
        content = PostMortemGenerator.to_markdown(data)
        media_type = "text/markdown"
        filename = f"postmortem-{incident_id}.md"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# WebSocket endpoint
@app.websocket("/api/ws/events")
async def websocket_events(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive loop
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# SSE endpoint
@app.get("/api/sse/events")
async def sse_events():
    async def event_generator():
        # Yield initial status
        yield f"data: {json.dumps({'type': 'CONNECTED', 'engine': 'BGP-Shield'})}\n\n"
        while True:
            await asyncio.sleep(1)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_bridge:app", host=API_HOST, port=API_PORT, reload=True)
