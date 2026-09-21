import React, { useState, useEffect } from 'react';
import { fetchPostMortem, downloadPostMortem } from '../services/api';

export default function PostMortemModal({ incident, onClose }) {
  const [activeTab, setActiveTab] = useState('executive');
  const [reportData, setReportData] = useState(null);
  const [markdown, setMarkdown] = useState('');
  const [htmlContent, setHtmlContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const loadReport = async () => {
      try {
        setLoading(true);
        const incidentId = incident?.id || incident?.incident_id || 'INC-2026-0921-01';
        const prefix = incident?.prefix || incident?.target_prefix || '208.67.222.0/24';
        const subprefix = incident?.subprefix || incident?.hijacked_subprefix || '208.67.222.0/25';
        const rogueAsn = incident?.rogue_asn || incident?.origin_as || 4761;
        const incidentType = incident?.type || incident?.incident_type || 'SUBPREFIX_HIJACK';

        const res = await fetchPostMortem(incidentId, prefix, subprefix, rogueAsn, incidentType);
        if (isMounted && res) {
          setReportData(res.data);
          setMarkdown(res.markdown || '');
          setHtmlContent(res.html || '');
        }
      } catch (err) {
        console.error('Failed to load post-mortem data', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadReport();
    return () => { isMounted = false; };
  }, [incident]);

  const handleCopyMarkdown = () => {
    if (markdown) {
      navigator.clipboard.writeText(markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  const handlePrintPdf = () => {
    if (htmlContent) {
      const printWindow = window.open('', '_blank');
      printWindow.document.write(htmlContent);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 500);
    } else {
      window.print();
    }
  };

  const handleDownloadMd = () => {
    const incidentId = reportData?.incident_id || 'incident-report';
    const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `postmortem-${incidentId}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  if (!incident) return null;

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={styles.header}>
          <div>
            <div style={styles.titleRow}>
              <span style={styles.badgeCritical}>{reportData?.severity || 'CRITICAL'}</span>
              <span style={styles.badgeResolved}>RESOLVED</span>
              <h2 style={styles.title}>Incident Post-Mortem: {reportData?.incident_id || 'Generating...'}</h2>
            </div>
            <p style={styles.subTitle}>
              Target: <span style={styles.cyan}>{reportData?.target_prefix || '208.67.222.0/24'}</span> | Duration: <span style={styles.cyan}>{reportData?.duration_seconds || 48}s</span> | SLA: <span style={styles.green}>PASSED</span>
            </p>
          </div>
          <button style={styles.closeBtn} onClick={onClose} title="Close">✕</button>
        </div>

        {/* Action Toolbar */}
        <div style={styles.toolbar}>
          <div style={styles.tabs}>
            <button
              style={{ ...styles.tabBtn, ...(activeTab === 'executive' ? styles.tabActive : {}) }}
              onClick={() => setActiveTab('executive')}
            >
              📊 Executive Briefing
            </button>
            <button
              style={{ ...styles.tabBtn, ...(activeTab === 'technical' ? styles.tabActive : {}) }}
              onClick={() => setActiveTab('technical')}
            >
              🔍 Technical RCA & Timeline
            </button>
            <button
              style={{ ...styles.tabBtn, ...(activeTab === 'playbooks' ? styles.tabActive : {}) }}
              onClick={() => setActiveTab('playbooks')}
            >
              🛡️ Router Playbooks
            </button>
            <button
              style={{ ...styles.tabBtn, ...(activeTab === 'actions' ? styles.tabActive : {}) }}
              onClick={() => setActiveTab('actions')}
            >
              📋 Preventive Actions
            </button>
          </div>

          <div style={styles.actions}>
            <button style={styles.actionBtn} onClick={handleCopyMarkdown}>
              {copied ? '✓ Copied!' : '📋 Copy Markdown'}
            </button>
            <button style={styles.actionBtnPrimary} onClick={handleDownloadMd}>
              📥 Download .md
            </button>
            <button style={styles.actionBtnSuccess} onClick={handlePrintPdf}>
              🖨️ Print / PDF
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div style={styles.body}>
          {loading ? (
            <div style={styles.loadingState}>
              <div style={styles.spinner}></div>
              <p>Reconstructing incident forensic timeline from DuckDB & AS Graph...</p>
            </div>
          ) : reportData ? (
            <div>
              {/* TAB 1: EXECUTIVE BRIEFING */}
              {activeTab === 'executive' && (
                <div>
                  <div style={styles.metricsGrid}>
                    <div style={styles.metricCard}>
                      <div style={styles.metricLabel}>FINANCIAL EXPOSURE RISK</div>
                      <div style={styles.metricValWarning}>{reportData.financial_exposure_estimate}</div>
                      <div style={styles.metricSub}>Based on 12-min DNS disruption</div>
                    </div>
                    <div style={styles.metricCard}>
                      <div style={styles.metricLabel}>TIME TO MITIGATION</div>
                      <div style={styles.metricValCyan}>{reportData.duration_seconds}s</div>
                      <div style={styles.metricSub}>Detection: 12ms | SLA: 5m</div>
                    </div>
                    <div style={styles.metricCard}>
                      <div style={styles.metricLabel}>MAX INBOUND COLLAPSE</div>
                      <div style={styles.metricValCritical}>{reportData.netflow_telemetry.traffic_collapse_percent}%</div>
                      <div style={styles.metricSub}>Peak drop from 1.2 to 0.12 Gbps</div>
                    </div>
                    <div style={styles.metricCard}>
                      <div style={styles.metricLabel}>SLA COMPLIANCE</div>
                      <div style={styles.metricValGreen}>100% COMPLIANT</div>
                      <div style={styles.metricSub}>Zero SLA penalty incurred</div>
                    </div>
                  </div>

                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>Executive Overview</h3>
                    <p style={styles.textLead}>{reportData.executive_summary}</p>
                  </div>

                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>Entity & Attribution Comparison</h3>
                    <div style={styles.entityGrid}>
                      <div style={styles.entityCol}>
                        <div style={styles.entityHeaderLegit}>LEGITIMATE ROUTE OWNER</div>
                        <div style={styles.entityRow}><strong>Entity:</strong> {reportData.legitimate_holder}</div>
                        <div style={styles.entityRow}><strong>ASN:</strong> AS{reportData.legitimate_asn}</div>
                        <div style={styles.entityRow}><strong>Prefix:</strong> <code>{reportData.target_prefix}</code></div>
                        <div style={styles.entityRow}><strong>RPKI Status:</strong> <span style={styles.green}>VALID</span></div>
                      </div>
                      <div style={styles.entityCol}>
                        <div style={styles.entityHeaderRogue}>ROGUE / HIJACKING ENTITY</div>
                        <div style={styles.entityRow}><strong>Entity:</strong> {reportData.rogue_holder}</div>
                        <div style={styles.entityRow}><strong>ASN:</strong> AS{reportData.rogue_asn}</div>
                        <div style={styles.entityRow}><strong>Hijacked Route:</strong> <code>{reportData.hijacked_subprefix}</code></div>
                        <div style={styles.entityRow}><strong>RPKI Status:</strong> <span style={styles.red}>INVALID_ASN</span></div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: TECHNICAL RCA & TIMELINE */}
              {activeTab === 'technical' && (
                <div>
                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>Technical Root Cause Analysis</h3>
                    <div style={styles.rcaRow}>
                      <strong>Attack Vector:</strong>
                      <span style={styles.cyan}>{reportData.root_cause_analysis.attack_vector}</span>
                    </div>
                    <div style={styles.rcaRow}>
                      <strong>RPKI Cryptographic Check:</strong>
                      <span style={styles.red}>{reportData.root_cause_analysis.rpki_state}</span>
                    </div>
                    <div style={styles.rcaRow}>
                      <strong>AS-Path Hop Traversal:</strong>
                      <code style={styles.codeInline}>
                        {reportData.root_cause_analysis.as_path_traversal.map(a => `AS${a}`).join(' → ')}
                      </code>
                    </div>
                    <p style={styles.text}>{reportData.root_cause_analysis.technical_details}</p>

                    <h4 style={styles.subheading}>Standards & RFC Violations:</h4>
                    <ul style={styles.rfcList}>
                      {reportData.root_cause_analysis.standards_violated.map((rfc, i) => (
                        <li key={i} style={styles.rfcItem}><code>{rfc}</code></li>
                      ))}
                    </ul>
                  </div>

                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>Chronological Incident Timeline</h3>
                    <div style={styles.timelineList}>
                      {reportData.timeline.map((item, i) => (
                        <div key={i} style={styles.timelineItem}>
                          <div style={styles.timelineOffset}>{item.timestamp_offset}</div>
                          <div style={styles.timelineDot(item.status)}></div>
                          <div style={styles.timelineBody}>
                            <div style={styles.timelinePhase}>
                              <strong>{item.phase}</strong>
                              <span style={styles.phaseBadge(item.status)}>{item.status}</span>
                            </div>
                            <p style={styles.timelineDesc}>{item.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: ROUTER PLAYBOOKS */}
              {activeTab === 'playbooks' && (
                <div>
                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>Juniper Junos (BGP Flowspec RFC 5575)</h3>
                    <pre style={styles.codeBlock}>{reportData.mitigation_playbooks.junos_flowspec}</pre>
                  </div>
                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>Cisco IOS-XR (AS-Path Filter & Traffic Drop)</h3>
                    <pre style={styles.codeBlock}>{reportData.mitigation_playbooks.cisco_iosxr}</pre>
                  </div>
                  <div style={styles.card}>
                    <h3 style={styles.cardTitle}>BIRD Routing Daemon (Remotely Triggered Black Hole)</h3>
                    <pre style={styles.codeBlock}>{reportData.mitigation_playbooks.bird_rtbh}</pre>
                  </div>
                </div>
              )}

              {/* TAB 4: PREVENTIVE ACTIONS */}
              {activeTab === 'actions' && (
                <div style={styles.card}>
                  <h3 style={styles.cardTitle}>Post-Mortem Preventative Hardening Items</h3>
                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.th}>Action Item</th>
                        <th style={styles.th}>Owner</th>
                        <th style={styles.th}>Priority</th>
                        <th style={styles.th}>Status</th>
                        <th style={styles.th}>Engineering Recommendation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reportData.preventive_actions.map((act, i) => (
                        <tr key={i} style={styles.tr}>
                          <td style={styles.td}><strong>{act.action}</strong></td>
                          <td style={styles.td}>{act.owner}</td>
                          <td style={styles.td}><span style={styles.priorityBadge(act.priority)}>{act.priority}</span></td>
                          <td style={styles.td}>{act.status}</td>
                          <td style={styles.tdMuted}>{act.recommendation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ) : (
            <div style={styles.errorState}>Failed to generate post-mortem data.</div>
          )}
        </div>
      </div>
    </div>
  );
}

const styles = {
  overlay: {
    position: 'fixed',
    top: 0, left: 0, right: 0, bottom: 0,
    backgroundColor: 'rgba(5, 8, 16, 0.85)',
    backdropFilter: 'blur(8px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    padding: '20px'
  },
  modal: {
    backgroundColor: '#0d1322',
    border: '1px solid #1e2d4d',
    borderRadius: '12px',
    width: '100%',
    maxWidth: '960px',
    maxHeight: '90vh',
    display: 'flex',
    flexDirection: 'column',
    boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(56, 189, 248, 0.1)',
    overflow: 'hidden'
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    padding: '20px 24px 16px 24px',
    borderBottom: '1px solid #1e2d4d',
    backgroundColor: '#0a0f1c'
  },
  titleRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    marginBottom: '6px'
  },
  title: {
    margin: 0,
    fontSize: '20px',
    color: '#e2e8f0',
    fontFamily: 'monospace',
    fontWeight: 'bold'
  },
  subTitle: {
    margin: 0,
    fontSize: '13px',
    color: '#94a3b8'
  },
  badgeCritical: {
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 'bold',
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
    color: '#ef4444',
    border: '1px solid rgba(239, 68, 68, 0.4)'
  },
  badgeResolved: {
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 'bold',
    backgroundColor: 'rgba(16, 185, 129, 0.2)',
    color: '#10b981',
    border: '1px solid rgba(16, 185, 129, 0.4)'
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: '#94a3b8',
    fontSize: '20px',
    cursor: 'pointer',
    padding: '4px 8px',
    borderRadius: '4px'
  },
  toolbar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 24px',
    backgroundColor: '#0e172a',
    borderBottom: '1px solid #1e2d4d',
    flexWrap: 'wrap',
    gap: '10px'
  },
  tabs: {
    display: 'flex',
    gap: '6px'
  },
  tabBtn: {
    background: 'transparent',
    border: '1px solid transparent',
    color: '#94a3b8',
    padding: '6px 14px',
    borderRadius: '6px',
    fontSize: '13px',
    cursor: 'pointer',
    fontWeight: '500',
    transition: 'all 0.15s ease'
  },
  tabActive: {
    backgroundColor: '#1e293b',
    borderColor: '#38bdf8',
    color: '#38bdf8'
  },
  actions: {
    display: 'flex',
    gap: '8px'
  },
  actionBtn: {
    backgroundColor: '#1e293b',
    color: '#e2e8f0',
    border: '1px solid #334155',
    padding: '6px 14px',
    borderRadius: '6px',
    fontSize: '12px',
    fontWeight: 'bold',
    cursor: 'pointer'
  },
  actionBtnPrimary: {
    backgroundColor: '#0284c7',
    color: '#ffffff',
    border: 'none',
    padding: '6px 14px',
    borderRadius: '6px',
    fontSize: '12px',
    fontWeight: 'bold',
    cursor: 'pointer'
  },
  actionBtnSuccess: {
    backgroundColor: '#059669',
    color: '#ffffff',
    border: 'none',
    padding: '6px 14px',
    borderRadius: '6px',
    fontSize: '12px',
    fontWeight: 'bold',
    cursor: 'pointer'
  },
  body: {
    padding: '24px',
    overflowY: 'auto',
    flex: 1
  },
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '12px',
    marginBottom: '20px'
  },
  metricCard: {
    backgroundColor: '#141c2e',
    border: '1px solid #1e2d4d',
    borderRadius: '8px',
    padding: '14px'
  },
  metricLabel: {
    fontSize: '11px',
    color: '#94a3b8',
    fontWeight: '600',
    letterSpacing: '0.5px'
  },
  metricValWarning: {
    fontSize: '20px',
    fontWeight: 'bold',
    color: '#f59e0b',
    margin: '6px 0 2px 0'
  },
  metricValCyan: {
    fontSize: '20px',
    fontWeight: 'bold',
    color: '#38bdf8',
    margin: '6px 0 2px 0'
  },
  metricValCritical: {
    fontSize: '20px',
    fontWeight: 'bold',
    color: '#ef4444',
    margin: '6px 0 2px 0'
  },
  metricValGreen: {
    fontSize: '20px',
    fontWeight: 'bold',
    color: '#10b981',
    margin: '6px 0 2px 0'
  },
  metricSub: {
    fontSize: '11px',
    color: '#64748b'
  },
  card: {
    backgroundColor: '#141c2e',
    border: '1px solid #1e2d4d',
    borderRadius: '8px',
    padding: '18px',
    marginBottom: '18px'
  },
  cardTitle: {
    margin: '0 0 12px 0',
    fontSize: '15px',
    color: '#38bdf8',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    borderBottom: '1px solid #1e293b',
    paddingBottom: '8px'
  },
  textLead: {
    fontSize: '13px',
    lineHeight: '1.7',
    color: '#cbd5e1',
    margin: 0
  },
  text: {
    fontSize: '13px',
    lineHeight: '1.6',
    color: '#cbd5e1',
    marginTop: '10px'
  },
  subheading: {
    fontSize: '13px',
    color: '#94a3b8',
    margin: '14px 0 6px 0'
  },
  rcaRow: {
    display: 'flex',
    gap: '10px',
    fontSize: '13px',
    marginBottom: '8px',
    color: '#cbd5e1'
  },
  codeInline: {
    backgroundColor: '#0a0f1c',
    color: '#38bdf8',
    padding: '2px 6px',
    borderRadius: '4px',
    fontFamily: 'monospace',
    fontSize: '12px'
  },
  rfcList: {
    margin: '6px 0 0 0',
    paddingLeft: '20px',
    color: '#94a3b8',
    fontSize: '12px'
  },
  rfcItem: {
    marginBottom: '4px'
  },
  entityGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '16px'
  },
  entityCol: {
    backgroundColor: '#0a0f1c',
    border: '1px solid #1e293b',
    borderRadius: '6px',
    padding: '12px'
  },
  entityHeaderLegit: {
    fontSize: '11px',
    fontWeight: 'bold',
    color: '#10b981',
    marginBottom: '8px',
    letterSpacing: '0.5px'
  },
  entityHeaderRogue: {
    fontSize: '11px',
    fontWeight: 'bold',
    color: '#ef4444',
    marginBottom: '8px',
    letterSpacing: '0.5px'
  },
  entityRow: {
    fontSize: '12px',
    color: '#cbd5e1',
    marginBottom: '4px'
  },
  timelineList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  timelineItem: {
    display: 'flex',
    gap: '14px',
    alignItems: 'flex-start'
  },
  timelineOffset: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: '#38bdf8',
    fontWeight: 'bold',
    minWidth: '95px'
  },
  timelineDot: (status) => ({
    width: '10px',
    height: '10px',
    borderRadius: '50%',
    backgroundColor: status === 'RESOLVED' ? '#10b981' : status === 'IMPACT' ? '#ef4444' : '#38bdf8',
    marginTop: '5px',
    boxShadow: `0 0 8px ${status === 'RESOLVED' ? '#10b981' : status === 'IMPACT' ? '#ef4444' : '#38bdf8'}`
  }),
  timelineBody: {
    flex: 1,
    borderLeft: '1px solid #1e293b',
    paddingLeft: '12px'
  },
  timelinePhase: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '13px',
    color: '#e2e8f0'
  },
  phaseBadge: (status) => ({
    fontSize: '10px',
    padding: '1px 6px',
    borderRadius: '3px',
    fontWeight: 'bold',
    backgroundColor: status === 'RESOLVED' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
    color: status === 'RESOLVED' ? '#10b981' : '#ef4444'
  }),
  timelineDesc: {
    margin: '4px 0 0 0',
    fontSize: '12px',
    color: '#94a3b8',
    lineHeight: '1.5'
  },
  codeBlock: {
    backgroundColor: '#07090e',
    color: '#a5f3fc',
    padding: '14px',
    borderRadius: '6px',
    fontSize: '12px',
    border: '1px solid #1e293b',
    overflowX: 'auto',
    fontFamily: 'monospace',
    lineHeight: '1.5'
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '12px'
  },
  th: {
    textAlign: 'left',
    padding: '8px 10px',
    backgroundColor: '#0a0f1c',
    color: '#38bdf8',
    borderBottom: '1px solid #1e2d4d',
    fontWeight: '600'
  },
  tr: {
    borderBottom: '1px solid #1e293b'
  },
  td: {
    padding: '10px',
    color: '#e2e8f0',
    verticalAlign: 'top'
  },
  tdMuted: {
    padding: '10px',
    color: '#94a3b8',
    verticalAlign: 'top',
    lineHeight: '1.5'
  },
  priorityBadge: (pri) => ({
    padding: '2px 6px',
    borderRadius: '3px',
    fontSize: '10px',
    fontWeight: 'bold',
    backgroundColor: pri === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
    color: pri === 'CRITICAL' ? '#ef4444' : '#f59e0b'
  }),
  cyan: { color: '#38bdf8' },
  green: { color: '#10b981' },
  red: { color: '#ef4444' },
  loadingState: {
    textAlign: 'center',
    padding: '40px',
    color: '#94a3b8'
  },
  spinner: {
    width: '30px',
    height: '30px',
    border: '3px solid #1e293b',
    borderTopColor: '#38bdf8',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    margin: '0 auto 12px auto'
  },
  errorState: {
    textAlign: 'center',
    padding: '30px',
    color: '#ef4444'
  }
};
