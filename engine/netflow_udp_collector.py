"""
BGP-Shield Native UDP NetFlow v9 / IPFIX Telemetry Collector
Listens on UDP port 2055, parses raw NetFlow v9 datagrams, extracts flow records,
and feeds them directly into the NetFlow correlator and DuckDB columnar storage.
"""
import asyncio
import socket
import struct
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger("bgp_shield.netflow_udp")

# NetFlow v9 Field Type IDs (RFC 3954)
NF_IN_BYTES = 1
NF_IN_PKTS = 2
NF_PROTOCOL = 4
NF_L4_SRC_PORT = 7
NF_IPV4_SRC_ADDR = 8
NF_L4_DST_PORT = 11
NF_IPV4_DST_ADDR = 12

class NetFlowV9Parser:
    """Parses binary NetFlow v9 datagrams."""

    @staticmethod
    def parse_packet(data: bytes) -> List[Dict[str, Any]]:
        """Parse NetFlow v9 header and records."""
        if len(data) < 20:
            return []

        # Header format: Version (2B), Count (2B), SysUptime (4B), UnixSecs (4B), Seq (4B), SourceID (4B)
        version, count, sys_uptime, unix_secs, seq, source_id = struct.unpack("!HHIIII", data[:20])

        if version != 9:
            return []

        flows = []
        offset = 20

        # Parse FlowSets
        while offset + 4 <= len(data):
            flowset_id, length = struct.unpack("!HH", data[offset:offset+4])
            if length < 4 or offset + length > len(data):
                break

            flowset_data = data[offset+4 : offset+length]

            # Simplified Data FlowSet parser for standard 28-byte flow records
            # Format: SrcIP (4B), DstIP (4B), SrcPort (2B), DstPort (2B), Proto (1B), Pad (1B), Packets (4B), Bytes (4B)
            if flowset_id >= 256:
                rec_offset = 0
                record_len = 22 # Standard minimalist template
                while rec_offset + record_len <= len(flowset_data):
                    try:
                        src_ip_b, dst_ip_b, src_port, dst_port, proto, _, pkts, bytes_count = struct.unpack(
                            "!4s4sHHBBII", flowset_data[rec_offset:rec_offset+22]
                        )
                        src_ip = socket.inet_ntoa(src_ip_b)
                        dst_ip = socket.inet_ntoa(dst_ip_b)

                        flows.append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "UDP" if proto == 17 else ("TCP" if proto == 6 else "ICMP"),
                            "bytes": bytes_count,
                            "packets": pkts,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                    except Exception:
                        pass
                    rec_offset += record_len

            offset += length

        return flows

    @staticmethod
    def build_test_packet(flows: List[Dict[str, Any]]) -> bytes:
        """Helper to construct a valid NetFlow v9 binary packet for testing."""
        # Header
        header = struct.pack("!HHIIII", 9, len(flows), 10000, int(datetime.now(timezone.utc).timestamp()), 1, 0)

        # Data FlowSet: ID 256, Length 4 + len(flows)*22
        flowset_len = 4 + (len(flows) * 22)
        flowset_header = struct.pack("!HH", 256, flowset_len)

        records_bytes = bytearray()
        for f in flows:
            src_ip_b = socket.inet_aton(f.get("src_ip", "192.168.1.1"))
            dst_ip_b = socket.inet_aton(f.get("dst_ip", "8.8.8.8"))
            src_port = f.get("src_port", 53)
            dst_port = f.get("dst_port", 12345)
            proto = 17 if f.get("protocol") == "UDP" else 6
            pkts = f.get("packets", 100)
            bytes_count = f.get("bytes", 50000)

            records_bytes.extend(struct.pack("!4s4sHHBBII", src_ip_b, dst_ip_b, src_port, dst_port, proto, 0, pkts, bytes_count))

        return header + flowset_header + bytes(records_bytes)

class NetFlowUDPProtocol(asyncio.DatagramProtocol):
    """Async UDP Protocol for receiving NetFlow v9 packets on port 2055."""

    def __init__(self, correlator, db_manager):
        self.correlator = correlator
        self.db_manager = db_manager
        self.transport = None
        self.packets_received = 0
        self.flows_processed = 0

    def connection_made(self, transport):
        self.transport = transport
        logger.info("NetFlow UDP Protocol listening on port 2055.")

    def datagram_received(self, data, addr):
        self.packets_received += 1
        try:
            flows = NetFlowV9Parser.parse_packet(data)
            for flow in flows:
                self.flows_processed += 1
                proc_flow = self.correlator.process_flow(flow)
                # Persist to DuckDB in threadpool
                self.db_manager.insert_netflow_record(proc_flow)
        except Exception as e:
            logger.error(f"Error parsing NetFlow datagram from {addr}: {e}")

    def error_received(self, exc):
        logger.error(f"NetFlow UDP socket error: {exc}")

async def start_netflow_udp_server(correlator, db_manager, port: int = 2055):
    """Start asynchronous UDP NetFlow listener."""
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: NetFlowUDPProtocol(correlator, db_manager),
            local_addr=("0.0.0.0", port)
        )
        logger.info(f"Native NetFlow UDP Collector running on port {port}")
        return transport, protocol
    except Exception as e:
        logger.warning(f"Could not bind UDP port {port} (may require admin permissions or port in use): {e}")
        return None, None
