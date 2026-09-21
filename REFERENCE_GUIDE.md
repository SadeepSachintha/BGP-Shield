# 📖 BGP-Shield: Technical Reference Guide & Operations Manual

A comprehensive technical reference for network operators, security engineers, and developers working with the **BGP-Shield Cyber Threat Intelligence & Route Leak Sentinel** platform.

---

## Table of Contents
1. [Architecture & Port Mapping](#1-architecture--port-mapping)
2. [API Reference: Python Stream Engine](#2-api-reference-python-stream-engine)
3. [API Reference: Laravel 12 Gateway](#3-api-reference-laravel-12-gateway)
4. [Data Dictionary & Database Schemas](#4-data-dictionary--database-schemas)
5. [Detection Algorithms & Standards](#5-detection-algorithms--standards)
6. [Router Mitigation Playbook Reference](#6-router-mitigation-playbook-reference)
7. [Chaos Scenarios & Attack Simulation](#7-chaos-scenarios--attack-simulation)
8. [Troubleshooting & Diagnostics](#8-troubleshooting--diagnostics)

---

## 1. Architecture & Port Mapping

| Service | Port | Protocol | Description |
| :--- | :--- | :--- | :--- |
| **Stream Analytics & API Bridge** | `8000` | HTTP / WebSocket | FastAPI engine, DuckDB OLAP store, RIPE RIS consumer |
| **Incident Gateway** | `8080` | HTTP | Laravel 12 API, alert policy manager, webhook dispatcher |
| **Visualization Console** | `5173` | HTTP | React 19 + Vite + D3.js Cyber Ops Command Center |
| **RIPE RIS Live WebSocket** | `443` | WSS (External) | `wss://ris-live.ripe.net/v1/ws/?client=bgp-shield-sentinel` |

---

## 2. API Reference: Python Stream Engine

**Base URL**: `http://127.0.0.1:8000`

### 1. `GET /api/status`
Returns real-time engine health, feed connectivity, and event processing counters.
```json
{
  "status": "ONLINE",
  "live_feed_connected": true,
  "messages_processed": 23410,
  "threats_detected": 1,
  "ws_clients": 1,
  "db_type": "DuckDB Columnar Store"
}
```

### 2. `GET /api/events`
Fetches recent BGP updates stored in DuckDB.
- **Query Parameters**:
  - `limit` (integer, default `50`): Maximum events to return.
  - `threats_only` (boolean, default `false`): Filter only flagged hijacks and route leaks.

### 3. `GET /api/incidents`
Returns active and resolved security incidents with forensic evidence.
- **Query Parameters**:
  - `limit` (integer, default `20`): Maximum records.

### 4. `GET /api/topology`
Returns nodes and links formatted for D3.js force-directed graph rendering.
```json
{
  "nodes": [
    {"id": "AS174", "asn": 174, "name": "Cogent Communications", "tier": "Tier-1 Backbone", "country": "Global"}
  ],
  "links": [
    {"source": "AS174", "target": "AS3356", "type": "P2P"}
  ]
}
```

### 5. `GET /api/netflow`
Returns aggregated NetFlow metrics and DDoS amplification vector breakdowns.
- Fields: `total_bytes`, `total_packets`, `ddos_events`, `peak_amplification`, `protocols`.

### 6. `POST /api/simulate/{scenario}`
Triggers an attack simulation:
- `subprefix_hijack`: Simulates Cisco OpenDNS `/25` hijack by rogue AS4761.
- `route_leak`: Simulates MainOne AS37282 leaking Cloudflare routes to Cogent.
- `ddos_amplification`: Simulates multi-gigabit Memcached & NTP reflection flood.

### 7. `POST /api/mitigate`
Generates router mitigation configurations.
- **Query Parameters**:
  - `prefix` (string, e.g. `208.67.222.0/25`)
  - `rogue_asn` (integer, e.g. `4761`)
  - `incident_type` (string, e.g. `SUBPREFIX_HIJACK`)

### 8. `WS /api/ws/events`
WebSocket endpoint streaming live BGP updates and high-priority incident alerts directly to connected UI clients.

---

## 3. API Reference: Laravel 12 Gateway

**Base URL**: `http://127.0.0.1:8080`

### 1. `GET /api/v1/incidents`
Lists incidents managed by the gateway with status filters.
- Query: `?status=DETECTED|INVESTIGATING|MITIGATED|RESOLVED`

### 2. `POST /api/v1/incidents`
Registers a new incident and automatically evaluates subscriber alert policies to trigger webhooks (Slack / PagerDuty).

### 3. `PATCH /api/v1/incidents/{id}/status`
Updates incident lifecycle state (`INVESTIGATING`, `MITIGATED`, `RESOLVED`).

### 4. `GET /api/v1/policies` & `POST /api/v1/policies`
CRUD endpoints for subscriber alert policies:
- Fields: `name`, `monitored_prefixes` (array), `monitored_asns` (array), `severity_threshold` (`LOW|MEDIUM|HIGH|CRITICAL`), `webhook_channel` (`SLACK|PAGERDUTY|WEBHOOK`), `webhook_url`.

### 5. `POST /api/v1/mitigation/generate`
Generates router playbooks and stores an associated `mitigation_actions` record.

### 6. `POST /api/v1/mitigation/{id}/apply`
Marks a mitigation action as applied and updates the parent incident status to `MITIGATED`.

---

## 4. Data Dictionary & Database Schemas

### DuckDB Columnar Schema (`engine/data/bgp_shield.duckdb`)

#### Table: `bgp_events`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | VARCHAR PRIMARY KEY | Unique event identifier (`ris-...` or `bgp-...`) |
| `timestamp` | TIMESTAMP | Event observation time in UTC |
| `event_type` | VARCHAR | `ANNOUNCE`, `WITHDRAW`, or `STATE` |
| `peer_ip` | VARCHAR | IP address of the reporting BGP peer |
| `peer_asn` | BIGINT | Autonomous System Number of reporting peer |
| `prefix` | VARCHAR | Announced IPv4 or IPv6 CIDR block |
| `origin_asn` | BIGINT | Origin Autonomous System (last hop in AS-Path) |
| `as_path` | VARCHAR (JSON) | Array of ASNs traversed |
| `path_length` | INTEGER | Total AS hops in path |
| `rpki_status` | VARCHAR | `VALID`, `INVALID_ASN`, `INVALID_LENGTH`, `NOT_FOUND` |
| `is_leak` | BOOLEAN | Route leak flag (Gao-Rexford violation) |
| `is_hijack` | BOOLEAN | Prefix hijack flag |
| `severity` | VARCHAR | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

#### Table: `netflow_records`
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | VARCHAR PRIMARY KEY | Unique flow identifier |
| `timestamp` | TIMESTAMP | Observation timestamp |
| `src_ip` / `dst_ip` | VARCHAR | Source and Destination IP addresses |
| `src_port` / `dst_port`| INTEGER | Layer 4 ports |
| `protocol` | VARCHAR | `TCP`, `UDP`, `ICMP` |
| `bytes` / `packets` | BIGINT | Volume of data in flow |
| `amplification_factor` | DOUBLE | Multiplier for reflection attacks |
| `is_ddos_vector` | BOOLEAN | Flagged volumetric reflection flood |
| `vector_type` | VARCHAR | e.g. `Memcached Reflection Flood`, `NTP Monlist` |

---

## 5. Detection Algorithms & Standards

### Gao-Rexford Model & Route Leaks (RFC 7908)
- **Economic Relationships**:
  - `Customer-to-Provider` ($C \to P$): Uphill phase. Customer pays provider for transit.
  - `Peer-to-Peer` ($P \leftrightarrow P$): Settlement-free peering. At most 1 hop.
  - `Provider-to-Customer` ($P \to C$): Downhill phase. Provider forwards to customer.
- **The Valley-Free Invariant**:
  Once a path enters the downhill ($P \to C$) or peering ($P \leftrightarrow P$) phase, it **cannot** transition back uphill ($C \to P$) or peer again.
- **Violation Flagging**:
  - Transition $P \to C \to P$: **Hairpin Transit Leak** (Critical)
  - Transition $P \leftrightarrow P \to P$: **Peer-to-Provider Leak** (High)

### RPKI BGP Origin Validation (RFC 6811)
- Compares announced prefix `P` and origin ASN `A` against Route Origin Authorizations (ROAs):
  $$\text{Status} = \begin{cases} 
  \text{VALID} & \text{if } A = \text{ROA.asn} \land \text{len}(P) \le \text{ROA.max\_length} \\
  \text{INVALID\_ASN} & \text{if } A \ne \text{ROA.asn} \\
  \text{INVALID\_LENGTH} & \text{if } \text{len}(P) > \text{ROA.max\_length} \\
  \text{NOT\_FOUND} & \text{if no covering ROA exists}
  \end{cases}$$

---

## 6. Router Mitigation Playbook Reference

### Juniper Junos (BGP Flowspec Discard)
```junos
set firewall family inet flow route drop-rogue-flow match destination 208.67.222.0/25
set firewall family inet flow route drop-rogue-flow then discard
commit comment "BGP-Shield Automated Mitigation for 208.67.222.0/25"
```

### Cisco IOS-XR (BGP Flowspec & AS-Path Filter)
```cisco
flowspec
 local-install interface all
 address-family ipv4
  class-map type traffic match-all CM-DROP-ROGUE-4761
   match destination-address 208.67.222.0/25
  !
  policy-map type traffic PM-BGP-SHIELD-DROP
   class CM-DROP-ROGUE-4761
    drop
  !
!
as-path-set ROGUE-ASN-4761
  ios-regex '_4761$'
end-set
!
route-policy DROP-ROGUE-ORIGIN
  if as-path in ROGUE-ASN-4761 then
    drop
  endif
end-policy
```

### BIRD Routing Daemon (RTBH Community `65535:666`)
```bird
filter rtbh_mitigation {
    if net = 208.67.222.0/25 then {
        bgp_community.add((65535, 666)); # RFC 7999 Blackhole Community
        dest = RTD_BLACKHOLE;
        accept;
    }
}
```

---

## 7. Chaos Scenarios & Attack Simulation

| Scenario Key | Attack Vector | Target Prefix | Rogue AS | Technical Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| `subprefix_hijack` | DNS Hijack / Crypto Interception | `208.67.222.0/25` | `AS4761` | Exploits Longest Prefix Match (LPM) over parent `/24`. |
| `route_leak` | Gao-Rexford Transit Hairpin Leak | `1.1.1.0/24` | `AS37282` | Multihomed customer leaks routes between Tier-1 providers. |
| `ddos_amplification` | Volumetric Reflection Flood | `8.8.8.0/24` | `N/A` | UDP reflection flood via Memcached (51,000x) and NTP (556x). |

---

## 8. Troubleshooting & Diagnostics

### Check if Port is in Use (PowerShell)
```powershell
Get-NetTCPConnection -LocalPort 8000, 8080, 5173 -ErrorAction SilentlyContinue | Select-Object LocalPort, OwningProcess
```

### Test Python Engine Endpoint
```bash
curl -s http://127.0.0.1:8000/api/status
```

### Test Laravel Gateway Endpoint
```bash
curl -s http://127.0.0.1:8080/api/v1/telemetry/status
```

### Run Automated Pytest Suite
```bash
python -m pytest engine/tests
```
