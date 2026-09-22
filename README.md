# 🛡️ BGP-Shield: Cyber Threat Intelligence & BGP Route Leak Sentinel

[![Python 3.14](https://img.shields.io/badge/Python-3.14-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Laravel 12](https://img.shields.io/badge/Laravel-12.x-red.svg?logo=laravel&logoColor=white)](https://laravel.com/)
[![React 19](https://img.shields.io/badge/React-19.x-61dafb.svg?logo=react&logoColor=black)](https://react.dev/)
[![DuckDB](https://img.shields.io/badge/DuckDB-1.5.5-yellow.svg?logo=duckdb&logoColor=black)](https://duckdb.org/)
[![D3.js](https://img.shields.io/badge/D3.js-7.9-orange.svg?logo=d3.js&logoColor=white)](https://d3js.org/)
[![Docker Compose](https://img.shields.io/badge/Docker_Compose-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![RIPE RIS Live](https://img.shields.io/badge/RIPE_RIS-Live_Stream-green.svg)](https://ris-live.ripe.net/)
[![RFC 7908](https://img.shields.io/badge/RFC-7908_Route_Leaks-purple.svg)](https://datatracker.ietf.org/doc/html/rfc7908)
[![RFC 8092](https://img.shields.io/badge/RFC-8092_Large_Communities-indigo.svg)](https://datatracker.ietf.org/doc/html/rfc8092)
[![RFC 5575](https://img.shields.io/badge/RFC-5575_BGP_Flowspec-blueviolet.svg)](https://datatracker.ietf.org/doc/html/rfc5575)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Aligned-crimson.svg)](https://attack.mitre.org/)

> An infrastructure-grade network observability and active defense platform that ingests raw Border Gateway Protocol (BGP) updates and NetFlow telemetry to detect malicious IP prefix hijacks, Gao-Rexford route leaks, and volumetric DDoS amplification vectors in real time.

---

## 📌 The Problem

Autonomous Systems (ASNs), cloud backbones, and financial infrastructure suffer catastrophic routing outages and silent traffic interception when transit providers misconfigure or maliciously manipulate BGP control-plane routes:
- **Silent Traffic Interception**: Traditional ICMP/HTTP monitors only detect outages *after* services fail and cannot detect unauthorized intermediate AS-path detours or state-sponsored surveillance.
- **Longest Prefix Match (LPM) Exploitation**: Adversaries announce more-specific subprefixes (e.g. `/25` of a legitimate `/24`), hijacking global traffic while the legitimate `/24` route appears active.
- **Gao-Rexford Route Leaks (RFC 7908)**: Misconfigured multihomed customers re-announce routes learned from one transit provider to another transit provider, creating massive transit black holes and choking regional peering links.
- **Volumetric DDoS Vectors**: Exploiting reflection amplification protocols (Memcached 51,000x, NTP 556x, DNS 54x, CLDAP) to overwhelm perimeter routers and saturate line cards.

**BGP-Shield** solves this by evaluating stateful AS-Path graph traversals over sliding windows, cross-verifying cryptographic RPKI Route Origin Authorizations (ROAs), correlating NetFlow telemetry, attributing adversarial intent via an Autonomous AI Threat Analyst, and generating automated perimeter router mitigations in sub-seconds.

---

## 🏛️ System Architecture

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
                                  │  - Hot flow/BGP records   │                              │   - Threat Analyst Engine │
                                  └─────────────┬─────────────┘                              └─────────────┬─────────────┘
                                                │                                                          │
                                                ▼                                                          ▼
                                  ┌───────────────────────────┐                              ┌───────────────────────────┐
                                  │   Laravel 12 API Gateway  │                              │ React 19 + D3.js Console  │
                                  │   - Incident Lifecycles   │                              │ - Force-Directed Topology │
                                  │   - Alert Policies        │                              │ - Live Radar Feed         │
                                  │   - Webhooks (Slack/PD)   │                              │ - AI Threat Intel Dossier │
                                  └───────────────────────────┘                              └───────────────────────────┘
```

---

## 🌟 Key Platform Capabilities

### 1. 🤖 Autonomous AI Threat Analyst & Intent Classifier
- **Intent Classification Engine**: Distinguishes operational blunders from hostile adversarial campaigns:
  - `STATE_SPONSORED_INTERCEPTION`: Identifies foreign state-owned or state-regulated transit entities (Rostelecom AS12389, China Telecom AS4134), path inflation, and strategic target sectors.
  - `FINANCIAL_CRYPTO_HIJACK`: Flags targeted `/24` subprefix hijacks against critical authoritative DNS (Amazon Route 53, Cloudflare DNS) and payment gateways.
  - `ISP_FAT_FINGER_MISCONFIG`: Differentiates Gao-Rexford peer-to-peer / provider-to-provider transit route leaks committed by multihomed stubs or regional ISPs.
  - `DDOS_AMPLIFICATION_ATTACK`: Correlates NetFlow volumetric spikes (>300–500%) with reflection reflection protocols (NTP, DNS, Memcached, CLDAP).
- **MITRE ATT&CK Enterprise Matrix Alignment**:
  - `T1584.004`: Compromise Infrastructure: DNS/BGP Server
  - `T1557.000`: Adversary-in-the-Middle (AiTM)
  - `T1498.001`: Direct Network Denial of Service: Volumetric
  - `T1565.002`: Transmitted Data Manipulation
- **High-Tech Cyber Defense Dossier Modal**: Radar gauges, confidence breakdown, forensic evidence chains, and prioritized containment playbooks.

### 2. 📜 Historical Internet BGP Disasters Replayer
Interactive archive browser allowing operators to replay and investigate famous real-world control-plane outages directly into the live BGP-Shield stream:
- **2008 Pakistan Telecom vs. YouTube Hijack**: AS36561 announced rogue `208.65.153.0/24` subprefix, propagated globally via PCCW (AS3491), blackholing YouTube for 2+ hours worldwide.
- **2018 Amazon Route 53 / MyEtherWallet DNS Hijack**: AS10297 hijacked `205.251.192.0/23` to reroute DNS queries to phishing servers in Russia, stealing $152,000+ in cryptocurrency.
- **2019 Cloudflare & DQE Gao-Rexford Route Leak**: AS33154 route optimizer leak forwarded through a regional steel mill ISP (AS39653) to AT&T (AS7018), routing massive global Cloudflare traffic through an overwhelmed 3 Gbps link.
- **2021 Rostelecom Global Tech Interception**: Russian state telco AS12389 announced unauthorized routes for 200+ major tech prefixes (Google, Cloudflare, Amazon, GoDaddy), steering Western traffic through Russian transit points.

### 3. ⏱️ Time-Travel Forensic Incident Replayer
- Interactive 5-step incident scrubber for deep post-incident analysis:
  1. *Pre-Attack Baseline*: Normal transit peering and baseline NetFlow volume.
  2. *Rogue Announcement*: Malicious `/25` subprefix or leaked announcement injected.
  3. *Global Propagation*: AS-path divergence across Tier-1 backbones.
  4. *Traffic Diversion*: Legitimate origin traffic collapses by $>65\%$.
  5. *Autonomous Mitigation*: Perimeter router flowspec/RTBH deployed and traffic restored.

### 4. 📝 Automated Incident Post-Mortem Report Generator
- Reconstructs complete incident Root Cause Analysis (RCA) with:
  - 5-Phase Incident Timelines (Detection, Path Divergence, Impact, Containment, Normalization).
  - RFC Citations & Standards Non-Compliance Analysis (`RFC 6811`, `RFC 7908`, `RFC 7454`).
  - NetFlow traffic drop and packet volume quantification.
  - Multi-tab UI with one-click **Markdown Export** and **Styled Print / PDF HTML Report**.

### 5. 🏷️ BGP Large Communities Decoder (RFC 8092 & RFC 1997) & PeeringDB
- Decodes standard (`NO_EXPORT`, `BLACKHOLE: 65535:666`) and 12-byte Large Communities (`ASN:Action:Target`) for Tier-1s (Cogent AS174, Lumen AS3356) and CDNs (Cloudflare AS13335).
- Enriches Autonomous Systems with **PeeringDB** metadata: peering policy (Open/Selective), public peering capacity (400G+), facility counts, and major IXP presences (Equinix, AMS-IX, DE-CIX, LINX).

### 6. 🌊 Native UDP NetFlow v9 / IPFIX Collector (`Port 2055`)
- High-throughput binary packet parser listening directly on UDP `port 2055`.
- Real-time amplification factor calculation and volumetric DDoS vector classification (Memcached, NTP Monlist, DNS ANY, CLDAP).

### 7. 🔒 Live Cloudflare RPKI ROA Synchronization
- Asynchronous synchronization engine pulling live cryptographic Route Origin Authorizations directly from Cloudflare's RPKI validator (`https://rpki.cloudflare.com/rpki.json`).

### 8. 🛡️ Autonomous Closed-Loop Router Mitigation
- Generates and deploys perimeter defense rules:
  - **Juniper Junos (BGP Flowspec — RFC 5575)**
  - **Cisco IOS-XR (BGP Flowspec & AS-Path Regex Filter)**
  - **BIRD Routing Daemon (RTBH Blackhole Community `65535:666`)**

---

## ⚡ Automated Router Mitigation Playbooks

When an incident is flagged, BGP-Shield automatically generates executable router configuration snippets ready for deployment:

### Juniper Junos (BGP Flowspec — RFC 5575)
```junos
# Juniper Junos BGP Flowspec Filter
set firewall family inet flow route drop-rogue-flow match destination 208.67.222.0/25
set firewall family inet flow route drop-rogue-flow then discard
commit comment "BGP-Shield Automated Mitigation for 208.67.222.0/25"
```

### Cisco IOS-XR (BGP Flowspec & AS-Path Filter)
```cisco
! Cisco IOS-XR BGP Flowspec Policy
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
! Cisco IOS-XR AS-Path Filter
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

### BIRD Routing Daemon (RTBH Blackhole — RFC 7999)
```bird
# BIRD Routing Daemon RTBH Trigger
filter rtbh_mitigation {
    if net = 208.67.222.0/25 then {
        bgp_community.add((65535, 666)); # Blackhole Community (RFC 7999)
        dest = RTD_BLACKHOLE;
        accept;
    }
}
```

---

## 📁 Repository Structure

```
BGP-Shield/
├── engine/                       # Python Stream Analytics & Storage Engine
│   ├── config.py                 # RIPE RIS endpoints, ROA table, AS relationships
│   ├── db_manager.py             # DuckDB columnar store & analytical queries
│   ├── as_graph_analyzer.py      # Gao-Rexford & RPKI detection algorithms
│   ├── netflow_correlator.py     # NetFlow & DDoS reflection vector correlator
│   ├── netflow_udp_collector.py  # Native UDP port 2055 NetFlow v9 listener
│   ├── ripe_ris_consumer.py      # Async RIPE RIS WebSocket consumer
│   ├── simulator.py              # Chaos attack scenario generator
│   ├── threat_analyst.py         # Autonomous AI Threat Analyst & MITRE ATT&CK
│   ├── historical_replayer.py    # Historical Internet BGP Disasters Replayer
│   ├── postmortem_generator.py   # Automated Incident Post-Mortem Generator
│   ├── bgp_communities_decoder.py# RFC 8092 Large Communities Decoder
│   ├── peeringdb_client.py       # PeeringDB IXP and interconnectivity client
│   ├── rpki_live_sync.py         # Cloudflare RPKI live sync client
│   ├── api_bridge.py             # FastAPI WebSocket/SSE & REST API
│   ├── Dockerfile                # Engine Docker container definition
│   └── tests/                    # 25 Pytest unit tests
├── backend/                      # Laravel 12 Incident Gateway
│   ├── app/
│   │   ├── Http/Controllers/     # Incident, Policy, Mitigation, Telemetry
│   │   ├── Models/               # Incident, AlertPolicy, MitigationAction
│   │   └── Services/             # WebhookDispatcher, MitigationPlaybookService
│   ├── Dockerfile                # Laravel Docker container definition
│   └── routes/api.php            # REST API endpoints (/api/v1/...)
├── frontend/                     # React 19 + Vite + D3.js Cyber Ops Console
│   ├── src/
│   │   ├── components/
│   │   │   ├── TopologyGraph.jsx         # D3 Force-Directed Mesh Graph (60 FPS)
│   │   │   ├── LiveRadarFeed.jsx         # Real-time BGP Ticker
│   │   │   ├── ForensicDiffModal.jsx     # Path Diff & Decoded Communities
│   │   │   ├── ThreatDossierModal.jsx    # AI Threat Intel Dossier (MITRE ATT&CK)
│   │   │   ├── HistoricalReplayModal.jsx # Famous BGP Disasters Archive
│   │   │   ├── PostMortemModal.jsx       # Automated Post-Mortem Generator
│   │   │   ├── AsnIntelligenceDrawer.jsx # PeeringDB IXP Metadata Drawer
│   │   │   ├── TimeTravelScrubber.jsx    # 5-Step Forensic Time-Travel Scrubber
│   │   │   ├── NetFlowTelemetry.jsx      # Flow Metrics & DDoS Amplification
│   │   │   ├── MitigationConsole.jsx     # Router Script Generator
│   │   │   ├── ChaosSimulator.jsx        # Attack Simulation Launcher
│   │   │   └── PolicySettings.jsx        # Alert Policies & Webhooks
│   │   ├── services/api.js               # WebSocket & REST Client
│   │   ├── App.jsx                       # Master Cyber Command Console
│   │   └── index.css                     # Vanilla CSS Cyber HUD Design System
│   ├── Dockerfile                        # Nginx production frontend container
│   └── nginx.conf                        # Reverse proxy routing
├── docker-compose.yml            # Multi-container orchestration
├── bgp_shield.bat                # Master interactive launcher
└── README.md
```

---

## 🚀 Getting Started

### Option A: Using the Consolidated Interactive Launcher (Windows)
```cmd
bgp_shield.bat
```
Interactive menu options:
- `[1]` **Start All Services** (Local Native: Engine + Gateway + Console)
- `[2]` **Stop All Services** (Clean Shutdown on ports 8000, 8080, 5173)
- `[3]` **Run Automated Pytest Suite** (Runs all 25 unit tests)
- `[4]` **Start Python Stream Engine Only** (`:8000` & UDP `:2055`)
- `[5]` **Start Laravel 12 Gateway Only** (`:8080`)
- `[6]` **Start React 19 Console Only** (`:5173`)
- `[D]` **Run Full Platform with Docker Compose** (`docker compose up --build -d`)
- `[S]` **Stop Docker Compose Containers** (`docker compose down`)

---

### Option B: Using Docker Compose
Build and launch the entire platform in isolated containers:
```bash
# Build and launch all containers
docker compose up --build -d

# View container status
docker compose ps

# View logs
docker compose logs -f

# Stop containers
docker compose down
```
Access the console at: `http://localhost:5173/`

---

### Option C: Manual Native Setup

#### 1. Python Stream Engine Setup
```bash
cd engine
pip install -r requirements.txt
python run_engine.py
```
*API & WebSocket hub starts on `http://127.0.0.1:8000`, NetFlow UDP on `2055`.*

#### 2. Laravel 12 Incident Gateway Setup
```bash
cd backend
composer install
php artisan migrate --force
php artisan db:seed --class=AlertPolicySeeder
php artisan serve --port=8080
```
*Gateway API runs on `http://127.0.0.1:8080`.*

#### 3. Frontend Visualization Console Setup
```bash
cd frontend
npm install
npm run dev -- --port 5173
```
*Open `http://localhost:5173/` in your browser.*

---

## 📡 API Reference

### Python Engine API (`http://127.0.0.1:8000`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Ingestion metrics, feed health, and processed counts |
| `GET` | `/api/events?limit=50&threats_only=false` | Recent BGP announcements from DuckDB |
| `GET` | `/api/incidents?limit=20` | Active security incidents with forensic JSON |
| `GET` | `/api/topology` | Nodes and links enriched with PeeringDB metadata |
| `GET` | `/api/as/{asn}/peeringdb` | PeeringDB facility count, IXPs, and peering policy |
| `POST` | `/api/communities/decode` | Decodes RFC 1997 & RFC 8092 BGP Large Communities |
| `GET` | `/api/incidents/{id}/threat-analysis` | Autonomous AI Threat Analysis & MITRE ATT&CK Dossier |
| `GET` | `/api/historical-incidents` | Catalog of famous historical BGP outages |
| `POST` | `/api/historical-incidents/replay` | Replays a famous BGP disaster into the live stream |
| `GET` | `/api/incidents/{id}/postmortem` | Structured post-mortem data with Markdown & HTML |
| `GET` | `/api/incidents/{id}/postmortem/download` | Download incident post-mortem report (.md or .html) |
| `GET` | `/api/time-travel/snapshots` | 5-step forensic time-travel scrubber snapshots |
| `GET` | `/api/rpki/status` | Live Cloudflare RPKI ROA count and sync metrics |
| `POST` | `/api/rpki/sync` | Triggers on-demand RPKI ROA synchronization |
| `GET` | `/api/netflow` | Flow metrics, packet counters, and DDoS vector breakdown |
| `POST` | `/api/simulate/{scenario}` | Triggers `subprefix_hijack`, `route_leak`, `ddos_amplification` |
| `POST` | `/api/mitigate` | Generates Junos, Cisco, and BIRD mitigation scripts |
| `WS` | `/api/ws/events` | Real-time WebSocket event broadcast stream |

### Laravel 12 Gateway API (`http://127.0.0.1:8080`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/incidents` | List all incidents with mitigation actions |
| `GET` | `/api/v1/incidents/{id}` | Single incident details with forensic data |
| `POST` | `/api/v1/incidents` | Report new incident and dispatch webhooks |
| `PATCH` | `/api/v1/incidents/{id}/status` | Update lifecycle (`INVESTIGATING`, `MITIGATED`, `RESOLVED`) |
| `GET` | `/api/v1/policies` | List subscriber alert policies |
| `POST` | `/api/v1/policies` | Create new alert policy (Slack, PagerDuty, Webhook) |
| `POST` | `/api/v1/mitigation/generate` | Generate and record mitigation action |
| `POST` | `/api/v1/mitigation/{id}/apply` | Mark mitigation as applied to edge routers |

---

## 🧪 Verification & Test Results

```
============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.1.0, pluggy-1.6.0
collected 25 items

engine\tests\test_as_graph.py ......                                     [ 24%]
engine\tests\test_communities_decoder.py ...                             [ 36%]
engine\tests\test_duckdb.py ...                                          [ 48%]
engine\tests\test_historical_replayer.py ...                             [ 60%]
engine\tests\test_netflow_udp.py .                                       [ 64%]
engine\tests\test_peeringdb.py ..                                        [ 72%]
engine\tests\test_postmortem.py ...                                      [ 84%]
engine\tests\test_threat_analyst.py ....                                 [100%]

============================= 25 passed in 2.35s ==============================
```

- **Unit Tests**: **25/25 passed** across 8 test suites covering the AS Graph analyzer, BGP communities decoder, DuckDB persistence, historical replayer, NetFlow UDP collector, PeeringDB client, post-mortem generator, and AI threat analyst.
- **Live Stream Ingestion**: Processed $>23,000$ real-world BGP messages from global route collectors via RIPE RIS Live.
- **Frontend Performance**: Optimized D3 force simulation with WebSocket event batching achieving a rock-solid **60 FPS** with minimal CPU overhead.
- **Production Build**: Vite production bundle compiled in **3.68s**.

---

## 📄 License

This project is open-source under the [MIT License](LICENSE). Built for high-velocity cyber threat intelligence, network routing resilience, and autonomous Internet defense.
