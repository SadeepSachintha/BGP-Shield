# 🛡️ BGP-Shield: Project Summary

**Cyber Threat Intelligence & BGP Route Leak Sentinel**  
*An Infrastructure-Grade Network Observability Platform*

---

## 1. Executive Summary

Border Gateway Protocol (BGP) is the routing fabric of the global internet. Originally designed on implicit trust, BGP remains inherently vulnerable to accidental misconfigurations and targeted prefix hijacks. Every year, Autonomous Systems (ASNs), cloud service providers, and financial institutions suffer catastrophic traffic outages, data interception, and routing blackholes when upstream transit providers inject rogue routes or leak customer peering routes.

**BGP-Shield** is an infrastructure-grade network observability platform designed to solve this critical vulnerability. It ingests raw Border Gateway Protocol telemetry directly from the global RIPE RIS (Routing Information Service) Live WebSocket stream and high-velocity NetFlow telemetry. Using stateful AS-Path graph traversals over sliding windows, RPKI ROA cryptographic verification, and columnar OLAP analytics, BGP-Shield detects:
1. **Sub-prefix & Exact-prefix Hijacks**: Exploitation of Longest Prefix Match (LPM) routing to silently intercept traffic.
2. **Gao-Rexford Valley-Free Route Leaks (RFC 7908)**: Unauthorized transit forwarding between peers and providers.
3. **Volumetric DDoS Amplification Vectors**: Memcached, NTP Monlist, and DNS reflection attacks correlated with routing modifications.
4. **Traffic Diversion Collapses**: Detecting sudden bandwidth drops coincident with unauthorized BGP announcements.

---

## 2. Technical Stack & Engineering Highlights

| Tier | Technology | Purpose & Capability |
| :--- | :--- | :--- |
| **Ingestion Engine** | Python 3.14 + `websockets` | Ingests real-time global BGP announcements from `wss://ris-live.ripe.net/v1/ws/` with async queue & worker pipeline. |
| **Stream Analytics** | Python 3.14 Stateful Graph Engine | Evaluates Gao-Rexford valley-free rules, RPKI ROA tables, and AS-hop prepending anomalies in $<10\text{ms}$. |
| **Hot & Analytical Storage** | DuckDB 1.5.5 | Columnar OLAP engine storing millions of flow and BGP records with sub-second aggregate SQL queries. |
| **Incident Gateway** | Laravel 12 + PHP 8.2 | Manages subscriber alert policies, webhook dispatchers (Slack, PagerDuty), and mitigation lifecycles. |
| **Visualization Console** | React 19 + D3.js 7.9 + Vite | Interactive force-directed AS-Path mesh topology graph, live radar feed, forensic route-diff modal, and chaos lab. |
| **Mitigation Playbooks** | RFC 5575 / RFC 7999 | Automated BGP Flowspec (Juniper/Cisco) and Remotely Triggered Black Hole (BIRD) script generation. |

---

## 3. Core Architectural Modules

```
                                  ┌───────────────────────────┐
                                  │   RIPE RIS Live WebSocket │
                                  │   (wss://ris-live.ripe.net)│
                                  └─────────────┬─────────────┘
                                                │
                                                ▼
┌───────────────────────────┐     ┌───────────────────────────┐     ┌───────────────────────────┐
│   Chaos Attack Simulator  │────▶│ Telemetry Ingestion Queue │────▶│   AS-Path Graph Analyzer  │
│  - Sub-prefix Hijacks     │     │ (Python 3.14 Async Worker)│     │  - Gao-Rexford Valley-Free│
│  - Gao-Rexford Leaks      │     └───────────────────────────┘     │  - RPKI ROA Validator    │
│  - DDoS Amplification     │                                       │  - Sub-prefix Hijacks     │
└───────────────────────────┘                                       └─────────────┬─────────────┘
                                                                                  │
                                                ┌─────────────────────────────────┴────────────────────────┐
                                                ▼                                                          ▼
                                  ┌───────────────────────────┐                              ┌───────────────────────────┐
                                  │  DuckDB Columnar Storage  │                              │   FastAPI API Bridge      │
                                  │  - Sub-second OLAP queries│                              │   - WebSocket & SSE Hub   │
                                  │  - Hot flow/BGP records   │                              │   - Mitigation Generator  │
                                  └─────────────┬─────────────┘                              └─────────────┬─────────────┘
                                                │                                                          │
                                                ▼                                                          ▼
                                  ┌───────────────────────────┐                              ┌───────────────────────────┐
                                  │   Laravel 12 API Gateway  │                              │ React 19 + D3.js Console  │
                                  │   - Incident Lifecycles   │                              │ - Force-Directed Topology │
                                  │   - Alert Policies        │                              │ - Live Radar Feed         │
                                  │   - Webhooks (Slack/PD)   │                              │ - Forensic Route Diff     │
                                  └───────────────────────────┘                              └───────────────────────────┘
```

### Key Engineering Capabilities:
- **Resilient Stream Ingestion**: Designed with an asynchronous queue buffer that decouples WebSocket message ingestion from database writes, preventing event-loop starvation during global route churn.
- **Sub-Second Forensic Correlation**: Links NetFlow telemetry drops with BGP route updates to confirm whether an unauthorized route announcement has successfully diverted real traffic.
- **Automated Mitigation Dispatch**: Generates router-specific configuration rules for Juniper Junos, Cisco IOS-XR, and BIRD routing daemons to drop or blackhole malicious traffic at perimeter borders.

---

## 4. Verification & Validation Summary

- **Automated Test Suite**: 9 unit tests in `engine/tests/` passed with 100% success rate:
  - RPKI validation logic (`VALID`, `INVALID_ASN`, `INVALID_LENGTH`).
  - Sub-prefix hijack detection (`/25` vs `/24`).
  - Gao-Rexford valley-free violation detection (`Provider -> Customer -> Provider` hairpin).
  - DuckDB columnar table creation, batch inserts, and analytical queries.
- **Live Stream Verification**: Connected to `wss://ris-live.ripe.net/v1/ws/?client=bgp-shield-sentinel` and processed $>23,000$ live updates from global route collectors without dropping packets.
- **Browser Subagent End-to-End Test**: Verified the full operational flow in the browser (`http://localhost:5173/`):
  1. Observed live HUD with active update counters and force-directed topology.
  2. Triggered sub-prefix hijack in the Chaos Lab.
  3. Verified instantaneous high-priority red alert card and topology highlight.
  4. Inspected the forensic diff modal with hop-by-hop traversal `AS174 -> AS3356 -> AS4761`.
  5. Verified generated BGP Flowspec and RTBH router scripts in the mitigation console.
