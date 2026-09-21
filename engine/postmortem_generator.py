"""
BGP-Shield Automated Incident Post-Mortem Report Generator
Produces Executive Summaries, Technical Root Cause Analyses (RCA),
Forensic Timelines, and Applied Mitigation Playbooks in Markdown and Print-Ready HTML.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class PostMortemGenerator:
    """Generates structured incident post-mortem data and formatted reports."""

    @staticmethod
    def generate_report_data(
        incident_id: Optional[str] = None,
        prefix: str = "208.67.222.0/24",
        hijacked_subprefix: str = "208.67.222.0/25",
        legitimate_asn: int = 36692,
        legitimate_holder: str = "Cisco OpenDNS",
        rogue_asn: int = 4761,
        rogue_holder: str = "Indosat Ooredoo / Rogue Peer",
        incident_type: str = "SUBPREFIX_HIJACK",
        severity: str = "CRITICAL",
        duration_seconds: int = 48,
        traffic_collapse_pct: float = 88.5
    ) -> Dict[str, Any]:
        """Construct a comprehensive incident data structure."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        inc_id = incident_id or f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-0472"

        return {
            "incident_id": inc_id,
            "generated_at": now_iso,
            "title": f"Security Incident Post-Mortem: {incident_type.replace('_', ' ').title()} on {prefix}",
            "severity": severity,
            "status": "RESOLVED / MITIGATED",
            "incident_type": incident_type,
            "target_prefix": prefix,
            "hijacked_subprefix": hijacked_subprefix,
            "legitimate_asn": legitimate_asn,
            "legitimate_holder": legitimate_holder,
            "rogue_asn": rogue_asn,
            "rogue_holder": rogue_holder,
            "duration_seconds": duration_seconds,
            "financial_exposure_estimate": "$142,500 USD",
            "sla_breach": "NO (Remediated in 48s, well within 5m SLA threshold)",
            "executive_summary": (
                f"On {now_iso}, BGP-Shield detected an unauthorized BGP announcement for {hijacked_subprefix} "
                f"originating from AS{rogue_asn} ({rogue_holder}). Because BGP prioritizes more-specific routes "
                f"(Longest Prefix Match), global Tier-1 transit providers diverted legitimate traffic away from "
                f"AS{legitimate_asn} ({legitimate_holder}), causing an {traffic_collapse_pct}% inbound traffic collapse. "
                f"BGP-Shield's automated defense engine detected the cryptographic RPKI origin invalidation within 12ms "
                f"and generated edge router mitigation playbooks, restoring full network connectivity in {duration_seconds} seconds."
            ),
            "root_cause_analysis": {
                "attack_vector": "Longest Prefix Match (LPM) Sub-Prefix Hijack",
                "standards_violated": [
                    "RFC 6811 - BGP Prefix Origin Validation (RPKI ROA)",
                    "RFC 7908 - Problem Definition and Classification of BGP Route Leaks",
                    "RFC 7454 - BGP Operations and Security Best Current Practices (BCP 194)"
                ],
                "rpki_state": "INVALID_ASN (Authorized origin: AS36692, Announced origin: AS4761)",
                "as_path_traversal": [174, 3356, rogue_asn],
                "transit_carriers_affected": ["Cogent Communications (AS174)", "Lumen Technologies (AS3356)"],
                "technical_details": (
                    f"Rogue AS{rogue_asn} announced prefix {hijacked_subprefix}, which is a subnet of legitimate "
                    f"prefix {prefix}. Global BGP routers automatically preferred the /25 over the /24 regardless of AS-Path "
                    f"length due to standard IP routing semantics. RPKI validation marked the announcement INVALID_ASN "
                    f"as the registered cryptographic ROA explicitly binds {prefix} to AS{legitimate_asn} with maxLength 24."
                )
            },
            "timeline": [
                {
                    "timestamp_offset": "T - 5m 00s",
                    "phase": "Baseline State",
                    "status": "NORMAL",
                    "description": f"Legitimate /24 announced by AS{legitimate_asn} via Tier-1 transit AS3356. RPKI ROA: VALID. Inbound flow: 1.2 Gbps."
                },
                {
                    "timestamp_offset": "T + 0m 00s",
                    "phase": "Rogue Announcement Injected",
                    "status": "DETECTED",
                    "description": f"Rogue AS{rogue_asn} announces unauthorized {hijacked_subprefix}. BGP-Shield triggers RPKI INVALID_ASN alert in 12ms."
                },
                {
                    "timestamp_offset": "T + 0m 12s",
                    "phase": "Global Transit Propagation",
                    "status": "PROPAGATING",
                    "description": "Tier-1 carriers (AS174, AS3356) accept and propagate /25 due to Longest Prefix Match rule."
                },
                {
                    "timestamp_offset": "T + 0m 35s",
                    "phase": "Traffic Diversion Collapse",
                    "status": "IMPACT",
                    "description": f"{traffic_collapse_pct}% inbound traffic collapse on legitimate origin AS{legitimate_asn}. NetFlow drops to 0.12 Gbps."
                },
                {
                    "timestamp_offset": "T + 0m 48s",
                    "phase": "Mitigation Deployed & Restored",
                    "status": "RESOLVED",
                    "description": "BGP Flowspec discard filter deployed across border routers. Covering route announced. Traffic restored to 1.18 Gbps."
                }
            ],
            "netflow_telemetry": {
                "baseline_bandwidth_gbps": 1.2,
                "trough_bandwidth_gbps": 0.12,
                "traffic_collapse_percent": traffic_collapse_pct,
                "estimated_dropped_packets": 14820000,
                "peak_rogue_diverted_flows": 450000
            },
            "mitigation_playbooks": {
                "junos_flowspec": (
                    f"# Juniper Junos BGP Flowspec Discard Policy\n"
                    f"set firewall family inet flow route drop-rogue-flow match destination {hijacked_subprefix}\n"
                    f"set firewall family inet flow route drop-rogue-flow then discard\n"
                    f"commit comment \"BGP-Shield Automated Mitigation for {hijacked_subprefix}\""
                ),
                "cisco_iosxr": (
                    f"! Cisco IOS-XR AS-Path Filter\n"
                    f"as-path-set ROGUE-ASN-{rogue_asn}\n"
                    f"  ios-regex '_{rogue_asn}$'\n"
                    f"end-set\n"
                    f"!\n"
                    f"route-policy DROP-ROGUE-ORIGIN\n"
                    f"  if as-path in ROGUE-ASN-{rogue_asn} then\n"
                    f"    drop\n"
                    f"  endif\n"
                    f"end-policy"
                ),
                "bird_rtbh": (
                    f"# BIRD Remotely Triggered Black Hole (RTBH)\n"
                    f"filter rtbh_mitigation {{\n"
                    f"    if net = {hijacked_subprefix} then {{\n"
                    f"        bgp_community.add((65535, 666)); # Blackhole Community (RFC 7999)\n"
                    f"        dest = RTD_BLACKHOLE;\n"
                    f"        accept;\n"
                    f"    }}\n"
                    f"}}"
                )
            },
            "preventive_actions": [
                {
                    "action": "RPKI ROA Granularity Hardening",
                    "owner": "Network Engineering",
                    "priority": "HIGH",
                    "status": "IN_PROGRESS",
                    "recommendation": f"Register explicit /25 and /26 ROAs for {prefix} in regional registries (ARIN / RIPE NCC) to eliminate sub-prefix hijacking surfaces."
                },
                {
                    "action": "Enforce Route Origin Validation (ROV) on Upstream BGP Sessions",
                    "owner": "NOC Operations",
                    "priority": "CRITICAL",
                    "status": "PLANNED",
                    "recommendation": "Configure all Tier-1 transit BGP peerings to automatically drop INVALID_ASN routes using local Routinator or Cloudflare RPKI RTR caches."
                },
                {
                    "action": "Deploy Autonomous System Provider Authorization (ASPA)",
                    "owner": "Architecture Team",
                    "priority": "MEDIUM",
                    "status": "PLANNED",
                    "recommendation": "Adopt RFC 9673 ASPA objects to prevent AS-path forgery and unauthorized upstream transit leaks."
                }
            ]
        }

    @staticmethod
    def to_markdown(data: Dict[str, Any]) -> str:
        """Convert structured post-mortem data into clean GitHub-flavored Markdown."""
        md = f"""# {data['title']}

> **Incident Reference**: `{data['incident_id']}`  
> **Classification**: `{data['severity']}` | **Status**: `{data['status']}`  
> **Generated**: {data['generated_at']}  
> **Duration**: {data['duration_seconds']} seconds | **SLA Impact**: {data['sla_breach']}

---

## 1. Executive Summary

{data['executive_summary']}

| Metric | Recorded Value |
| :--- | :--- |
| **Target Legitimate Prefix** | `{data['target_prefix']}` ({data['legitimate_holder']} - AS{data['legitimate_asn']}) |
| **Hijacked Sub-Prefix** | `{data['hijacked_subprefix']}` |
| **Rogue Origin Entity** | `{data['rogue_holder']}` (AS{data['rogue_asn']}) |
| **Max Inbound Traffic Collapse** | **{data['netflow_telemetry']['traffic_collapse_percent']}%** |
| **Estimated Dropped Packets** | ~{data['netflow_telemetry']['estimated_dropped_packets']:,} packets |
| **Estimated Financial Exposure** | {data['financial_exposure_estimate']} |
| **Time to Detection (TTD)** | **12 ms** |
| **Time to Mitigation (TTM)** | **48 seconds** |

---

## 2. Technical Root Cause Analysis (RCA)

- **Attack Vector**: {data['root_cause_analysis']['attack_vector']}
- **RPKI ROA State**: `{data['root_cause_analysis']['rpki_state']}`
- **Transit Path Traversed**: `{' -> '.join(f'AS{asn}' for asn in data['root_cause_analysis']['as_path_traversal'])}`
- **Affected Transit Carriers**: {', '.join(data['root_cause_analysis']['transit_carriers_affected'])}

### Standards & RFC Violations:
"""
        for rfc in data['root_cause_analysis']['standards_violated']:
            md += f"- `{rfc}`\n"

        md += f"\n### Mechanics:\n{data['root_cause_analysis']['technical_details']}\n\n---\n\n## 3. Incident Timeline\n\n"

        for item in data['timeline']:
            md += f"### `[{item['timestamp_offset']}]` {item['phase']} ({item['status']})\n"
            md += f"{item['description']}\n\n"

        md += "---\n\n## 4. Applied Router Mitigations\n\n"

        md += f"### Juniper Junos (BGP Flowspec RFC 5575)\n```junos\n{data['mitigation_playbooks']['junos_flowspec']}\n```\n\n"
        md += f"### Cisco IOS-XR (AS-Path Regex Origin Drop)\n```cisco\n{data['mitigation_playbooks']['cisco_iosxr']}\n```\n\n"
        md += f"### BIRD Daemon (Remotely Triggered Black Hole)\n```bird\n{data['mitigation_playbooks']['bird_rtbh']}\n```\n\n"

        md += "---\n\n## 5. Preventative Action Items\n\n"
        md += "| Action Item | Owner | Priority | Status | Recommendation |\n"
        md += "| :--- | :--- | :--- | :--- | :--- |\n"
        for act in data['preventive_actions']:
            md += f"| **{act['action']}** | {act['owner']} | `{act['priority']}` | `{act['status']}` | {act['recommendation']} |\n"

        md += f"\n---\n*Report generated by BGP-Shield Sentinel Engine - Incident Forensics Module.*"
        return md

    @staticmethod
    def to_html(data: Dict[str, Any]) -> str:
        """Convert structured post-mortem data into a print-ready, professional HTML report."""
        timeline_html = "".join(f"""
            <div class="timeline-entry">
                <div class="timeline-time">{item['timestamp_offset']}</div>
                <div class="timeline-content">
                    <strong>{item['phase']}</strong> <span class="badge {item['status'].lower()}">{item['status']}</span>
                    <p>{item['description']}</p>
                </div>
            </div>
        """ for item in data['timeline'])

        actions_html = "".join(f"""
            <tr>
                <td><strong>{act['action']}</strong></td>
                <td>{act['owner']}</td>
                <td><span class="badge priority-{act['priority'].lower()}">{act['priority']}</span></td>
                <td>{act['status']}</td>
                <td>{act['recommendation']}</td>
            </tr>
        """ for act in data['preventive_actions'])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{data['title']} - BGP-Shield Post-Mortem</title>
    <style>
        :root {{
            --bg-color: #0c0f17;
            --surface-color: #141b2d;
            --border-color: #1f2a48;
            --text-color: #e2e8f0;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --critical: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
        }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; font-size: 11pt; }}
            .no-print {{ display: none !important; }}
            .card {{ border: 1px solid #ccc !important; background: #fff !important; box-shadow: none !important; }}
            pre {{ background: #f4f4f4 !important; color: #000 !important; border: 1px solid #ddd !important; }}
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 30px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid var(--border-color); padding-bottom: 20px; margin-bottom: 25px; }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 24px; color: var(--primary); }}
        .meta-bar {{ display: flex; gap: 15px; font-size: 13px; color: var(--text-muted); flex-wrap: wrap; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge.resolved {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}
        .card {{ background: var(--surface-color); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
        .card h2 {{ margin-top: 0; font-size: 18px; color: var(--text-color); border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
        th, td {{ padding: 10px; border: 1px solid var(--border-color); text-align: left; }}
        th {{ background: rgba(255,255,255,0.03); color: var(--primary); }}
        pre {{ background: #07090e; color: #a5f3fc; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: 1px solid #1e293b; }}
        .timeline-entry {{ display: flex; gap: 15px; margin-bottom: 15px; }}
        .timeline-time {{ font-family: monospace; font-weight: bold; color: var(--primary); min-width: 95px; }}
        .timeline-content {{ border-left: 2px solid var(--border-color); padding-left: 15px; }}
        .print-btn {{ background: var(--primary); color: #000; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; cursor: pointer; float: right; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="no-print" style="margin-bottom: 20px; overflow: hidden;">
            <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
        </div>
        <div class="header">
            <h1>{data['title']}</h1>
            <div class="meta-bar">
                <span><strong>ID:</strong> {data['incident_id']}</span>
                <span><strong>Date:</strong> {data['generated_at']}</span>
                <span><strong>Severity:</strong> <span class="badge critical">{data['severity']}</span></span>
                <span><strong>Status:</strong> <span class="badge resolved">{data['status']}</span></span>
                <span><strong>Duration:</strong> {data['duration_seconds']}s</span>
            </div>
        </div>

        <div class="card">
            <h2>1. Executive Summary</h2>
            <p>{data['executive_summary']}</p>
            <table>
                <tr><th>Metric</th><th>Recorded Value</th></tr>
                <tr><td>Target Prefix</td><td><code>{data['target_prefix']}</code> ({data['legitimate_holder']} - AS{data['legitimate_asn']})</td></tr>
                <tr><td>Hijacked Sub-Prefix</td><td><code>{data['hijacked_subprefix']}</code></td></tr>
                <tr><td>Rogue Entity</td><td><code>{data['rogue_holder']}</code> (AS{data['rogue_asn']})</td></tr>
                <tr><td>Traffic Collapse</td><td><strong>{data['netflow_telemetry']['traffic_collapse_percent']}%</strong></td></tr>
                <tr><td>Estimated Financial Exposure</td><td>{data['financial_exposure_estimate']}</td></tr>
                <tr><td>Time to Detection</td><td><strong>12 ms</strong></td></tr>
                <tr><td>Time to Mitigation</td><td><strong>{data['duration_seconds']} seconds</strong></td></tr>
            </table>
        </div>

        <div class="card">
            <h2>2. Technical Root Cause Analysis</h2>
            <p><strong>Vector:</strong> {data['root_cause_analysis']['attack_vector']}</p>
            <p><strong>RPKI State:</strong> <code>{data['root_cause_analysis']['rpki_state']}</code></p>
            <p><strong>AS-Path:</strong> {' &rarr; '.join(f'AS{a}' for a in data['root_cause_analysis']['as_path_traversal'])}</p>
            <p>{data['root_cause_analysis']['technical_details']}</p>
        </div>

        <div class="card">
            <h2>3. Incident Timeline</h2>
            {timeline_html}
        </div>

        <div class="card">
            <h2>4. Applied Router Mitigations</h2>
            <h3>Juniper Junos (Flowspec RFC 5575)</h3>
            <pre>{data['mitigation_playbooks']['junos_flowspec']}</pre>
            <h3>Cisco IOS-XR</h3>
            <pre>{data['mitigation_playbooks']['cisco_iosxr']}</pre>
        </div>

        <div class="card">
            <h2>5. Preventative Action Items</h2>
            <table>
                <thead>
                    <tr><th>Action</th><th>Owner</th><th>Priority</th><th>Status</th><th>Recommendation</th></tr>
                </thead>
                <tbody>
                    {actions_html}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        return html
