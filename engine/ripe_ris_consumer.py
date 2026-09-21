"""
BGP-Shield RIPE RIS Live WebSocket Consumer
Connects to the public RIPE RIS Live stream (wss://ris-live.ripe.net/v1/ws/?client=bgp-shield-sentinel)
and ingests global real-time BGP announcements, withdrawals, and AS-paths.
Uses an async queue and worker pipeline to prevent event loop starvation.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional
import websockets
from config import RIPE_RIS_WS_URL, RIPE_RIS_CLIENT_ID

logger = logging.getLogger("bgp_shield.ris_consumer")

class RipeRisConsumer:
    def __init__(self, analyzer, db_manager, on_event_callback: Optional[Callable] = None):
        self.analyzer = analyzer
        self.db_manager = db_manager
        self.on_event_callback = on_event_callback
        self.running = False
        self.connected = False
        self.messages_processed = 0
        self.threats_detected = 0
        self.queue = asyncio.Queue(maxsize=1000)

    async def start(self):
        """Start async WebSocket ingestion loop and processor worker."""
        self.running = True
        logger.info(f"Starting RIPE RIS consumer connecting to {RIPE_RIS_WS_URL}")

        # Start background processor task
        processor_task = asyncio.create_task(self._process_queue())

        backoff = 2
        while self.running:
            try:
                async with websockets.connect(
                    RIPE_RIS_WS_URL,
                    ping_interval=20,
                    ping_timeout=15
                ) as ws:
                    self.connected = True
                    backoff = 2
                    logger.info("Connected to RIPE RIS Live stream.")

                    # Subscribe to BGP UPDATE messages
                    subscribe_msg = {
                        "type": "ris_subscribe",
                        "data": {
                            "type": "UPDATE",
                            "require": "announcements"
                        }
                    }
                    await ws.send(json.dumps(subscribe_msg))

                    while self.running:
                        raw_msg = await ws.recv()
                        try:
                            msg = json.loads(raw_msg)
                            # Put in queue if space available, drop oldest if full
                            if self.queue.full():
                                try:
                                    self.queue.get_nowait()
                                except asyncio.QueueEmpty:
                                    pass
                            await self.queue.put(msg)
                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            logger.error(f"Error queueing RIS message: {e}")

            except (websockets.ConnectionClosed, OSError) as e:
                self.connected = False
                logger.warning(f"RIPE RIS connection lost: {e}. Retrying in {backoff}s...")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
            except asyncio.CancelledError:
                self.running = False
                break
            except Exception as e:
                self.connected = False
                logger.error(f"Unexpected error in RIPE RIS consumer: {e}")
                await asyncio.sleep(5)

        processor_task.cancel()

    def stop(self):
        """Stop the consumer loop."""
        self.running = False
        self.connected = False

    async def _process_queue(self):
        """Worker task processing BGP messages from the queue asynchronously."""
        while self.running:
            try:
                msg = await self.queue.get()
                await self._handle_ris_message(msg)
                self.queue.task_done()
                # Yield control to allow HTTP and WebSocket events to breathe
                await asyncio.sleep(0.005)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queue processor error: {e}")
                await asyncio.sleep(0.01)

    async def _handle_ris_message(self, msg: dict):
        """Process incoming RIPE RIS message."""
        if msg.get("type") != "ris_message":
            return

        data = msg.get("data", {})
        peer = data.get("peer", "")
        peer_asn = data.get("peer_asn", 0)
        raw_path = data.get("path", [])
        
        # Flatten and filter as_path integers
        as_path = []
        for item in raw_path:
            if isinstance(item, int):
                as_path.append(item)
            elif isinstance(item, list):
                as_path.extend([x for x in item if isinstance(x, int)])

        if not as_path:
            return

        announcements = data.get("announcements", [])
        for ann in announcements:
            prefixes = ann.get("prefixes", [])
            for prefix in prefixes:
                self.messages_processed += 1
                origin_asn = as_path[-1]

                # Run stateful AS graph & RPKI analysis
                analysis = self.analyzer.analyze_as_path(as_path, prefix)

                # Offload DB writes to threadpool
                await asyncio.to_thread(self._persist_event, as_path, prefix, origin_asn, peer, peer_asn, analysis)

    def _persist_event(self, as_path, prefix, origin_asn, peer, peer_asn, analysis):
        # Record topology links in DuckDB
        for i in range(len(as_path) - 1):
            rel = self.analyzer.get_as_relationship(as_path[i], as_path[i+1])
            self.db_manager.record_as_link(as_path[i], as_path[i+1], rel)

        event_id = f"ris-{uuid.uuid4().hex[:8]}"
        bgp_event = {
            "id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "ANNOUNCE",
            "peer_ip": peer,
            "peer_asn": peer_asn,
            "prefix": prefix,
            "origin_asn": origin_asn,
            "as_path": as_path,
            "path_length": len(as_path),
            "rpki_status": analysis["rpki_status"],
            "is_leak": analysis["is_leak"],
            "leak_type": analysis["leak_info"]["type"] if analysis["leak_info"] else "NONE",
            "is_hijack": analysis["is_hijack"],
            "hijack_type": analysis["hijack_info"]["type"] if analysis["hijack_info"] else "NONE",
            "severity": analysis["severity"],
            "details": analysis
        }

        # Persist to DuckDB
        self.db_manager.insert_bgp_event(bgp_event)

        if analysis["is_threat"]:
            self.threats_detected += 1
            incident = {
                "id": f"inc-{uuid.uuid4().hex[:8]}",
                "incident_type": analysis["hijack_info"]["type"] if analysis["is_hijack"] else (
                    analysis["leak_info"]["type"] if analysis["is_leak"] else "RPKI_VIOLATION"
                ),
                "severity": analysis["severity"],
                "target_prefix": prefix,
                "victim_asn": analysis["roa_info"]["asn"] if analysis.get("roa_info") else 0,
                "victim_name": analysis["roa_info"].get("holder", "Unknown") if analysis.get("roa_info") else "Unknown",
                "attacker_asn": origin_asn,
                "attacker_name": f"AS{origin_asn}",
                "status": "DETECTED",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "details_json": analysis
            }
            self.db_manager.record_incident(incident)

        # Dispatch callback
        if self.on_event_callback:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.on_event_callback(bgp_event), loop)
            except Exception:
                pass
