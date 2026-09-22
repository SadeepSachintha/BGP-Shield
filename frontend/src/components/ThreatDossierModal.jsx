import React, { useState, useEffect } from 'react';
import { fetchThreatAnalysis } from '../services/api';

export default function ThreatDossierModal({ incident, onClose }) {
  const [loading, setLoading] = useState(true);
  const [dossier, setDossier] = useState(null);
  const [activeTab, setActiveTab] = useState('attribution'); // 'attribution' | 'mitre' | 'evidence' | 'countermeasures'

  useEffect(() => {
    if (!incident) return;
    setLoading(true);
    fetchThreatAnalysis(incident.id || 'INC-DEMO-01')
      .then((data) => {
        setDossier(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to load threat analysis:', err);
        setLoading(false);
      });
  }, [incident]);

  if (!incident) return null;

  const getSeverityColor = (score) => {
    if (score >= 80) return '#ff3366';
    if (score >= 65) return '#f59e0b';
    return '#00ffcc';
  };

  const getIntentBadgeStyle = (intent) => {
    switch (intent) {
      case 'STATE_SPONSORED_INTERCEPTION':
        return { background: 'rgba(255, 51, 102, 0.15)', color: '#ff3366', border: '1px solid rgba(255, 51, 102, 0.4)' };
      case 'FINANCIAL_CRYPTO_HIJACK':
        return { background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.4)' };
      case 'ISP_FAT_FINGER_MISCONFIG':
        return { background: 'rgba(0, 112, 243, 0.15)', color: '#0070f3', border: '1px solid rgba(0, 112, 243, 0.4)' };
      case 'DDOS_AMPLIFICATION_ATTACK':
        return { background: 'rgba(121, 40, 202, 0.15)', color: '#7928ca', border: '1px solid rgba(121, 40, 202, 0.4)' };
      default:
        return { background: 'rgba(0, 255, 204, 0.15)', color: '#00ffcc', border: '1px solid rgba(0, 255, 204, 0.4)' };
    }
  };

  const formatIntentName = (intent) => {
    return intent ? intent.replace(/_/g, ' ') : 'UNKNOWN';
  };

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={styles.header}>
          <div>
            <div style={styles.badgeRow}>
              <span style={styles.intelBadge}>AI SENTINEL INTEL</span>
              <span style={styles.incidentTag}>{incident.id || 'INC-LIVE'}</span>
            </div>
            <h2 style={styles.title}>Autonomous AI Threat Intelligence Dossier</h2>
            <div style={styles.subtitle}>
              Target: <span style={styles.highlight}>{incident.target_prefix || '208.67.222.0/24'}</span> | 
              Victim: <span style={styles.highlight}>AS{incident.victim_asn || 36692}</span> vs 
              Attacker: <span style={{ ...styles.highlight, color: '#ff3366' }}>AS{incident.attacker_asn || 4761}</span>
            </div>
          </div>
          <button style={styles.closeBtn} onClick={onClose} title="Close Dossier">✕</button>
        </div>

        {loading ? (
          <div style={styles.loadingContainer}>
            <div style={styles.spinner} />
            <div style={{ marginTop: '16px', color: '#8892b0', fontSize: '14px', fontFamily: 'monospace' }}>
              Synthesizing intent attribution heuristics, RPKI cryptanalysis & MITRE ATT&CK mapping...
            </div>
          </div>
        ) : !dossier ? (
          <div style={styles.loadingContainer}>
            <p style={{ color: '#ff3366' }}>Failed to generate threat dossier.</p>
          </div>
        ) : (
          <div style={styles.content}>
            {/* Top Score Matrix Banner */}
            <div style={styles.bannerGrid}>
              {/* Score Card */}
              <div style={styles.scoreCard}>
                <div style={styles.cardLabel}>THREAT SEVERITY INDEX</div>
                <div style={{ ...styles.scoreValue, color: getSeverityColor(dossier.threat_severity_score) }}>
                  {dossier.threat_severity_score}
                  <span style={styles.scoreMax}>/100</span>
                </div>
                <div style={{ ...styles.ratingTag, borderColor: getSeverityColor(dossier.threat_severity_score) }}>
                  {dossier.threat_rating}
                </div>
              </div>

              {/* Attribution Card */}
              <div style={styles.attributionCard}>
                <div style={styles.cardLabel}>PRIMARY INTENT ATTRIBUTION</div>
                <div style={{ ...styles.intentBadge, ...getIntentBadgeStyle(dossier.primary_intent) }}>
                  {formatIntentName(dossier.primary_intent)}
                </div>
                <div style={styles.confidenceBarContainer}>
                  <div style={styles.confidenceLabel}>
                    <span>Attribution Confidence</span>
                    <span style={{ color: '#00ffcc', fontWeight: 'bold' }}>{dossier.confidence_pct}%</span>
                  </div>
                  <div style={styles.progressBarBg}>
                    <div
                      style={{
                        ...styles.progressBarFill,
                        width: `${dossier.confidence_pct}%`,
                        backgroundColor: getSeverityColor(dossier.threat_severity_score)
                      }}
                    />
                  </div>
                </div>
              </div>

              {/* Telemetry Vectors */}
              <div style={styles.telemetryCard}>
                <div style={styles.cardLabel}>KEY VECTOR ATTRIBUTES</div>
                <div style={styles.vectorList}>
                  <div style={styles.vectorItem}>
                    <span style={styles.vectorKey}>State-Aligned Transit:</span>
                    <span style={{ color: dossier.is_state_sponsored ? '#ff3366' : '#8892b0', fontWeight: 'bold' }}>
                      {dossier.is_state_sponsored ? 'DETECTED' : 'NEGATIVE'}
                    </span>
                  </div>
                  <div style={styles.vectorItem}>
                    <span style={styles.vectorKey}>High-Value Target:</span>
                    <span style={{ color: dossier.is_high_value_target ? '#f59e0b' : '#8892b0', fontWeight: 'bold' }}>
                      {dossier.is_high_value_target ? 'CONFIRMED' : 'STANDARD'}
                    </span>
                  </div>
                  <div style={styles.vectorItem}>
                    <span style={styles.vectorKey}>RPKI Validation:</span>
                    <span style={{ color: incident.rpki_status === 'INVALID' ? '#ff3366' : '#00ffcc', fontWeight: 'bold' }}>
                      {incident.rpki_status || 'UNKNOWN'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div style={styles.tabBar}>
              <button
                style={{ ...styles.tabBtn, ...(activeTab === 'attribution' ? styles.tabBtnActive : {}) }}
                onClick={() => setActiveTab('attribution')}
              >
                📊 Intent Probabilities
              </button>
              <button
                style={{ ...styles.tabBtn, ...(activeTab === 'mitre' ? styles.tabBtnActive : {}) }}
                onClick={() => setActiveTab('mitre')}
              >
                🎯 MITRE ATT&CK Matrix ({dossier.mitre_attack_matrix.length})
              </button>
              <button
                style={{ ...styles.tabBtn, ...(activeTab === 'evidence' ? styles.tabBtnActive : {}) }}
                onClick={() => setActiveTab('evidence')}
              >
                🔍 Forensic Evidence ({dossier.forensic_evidence.length})
              </button>
              <button
                style={{ ...styles.tabBtn, ...(activeTab === 'countermeasures' ? styles.tabBtnActive : {}) }}
                onClick={() => setActiveTab('countermeasures')}
              >
                🛡️ Countermeasures ({dossier.strategic_countermeasures.length})
              </button>
            </div>

            {/* Tab Body */}
            <div style={styles.tabContent}>
              {/* Tab 1: Intent Probabilities */}
              {activeTab === 'attribution' && (
                <div>
                  <h4 style={styles.sectionHeading}>Calculated Intent Probability Breakdown</h4>
                  <p style={styles.sectionDesc}>
                    Multi-factor Bayesian classification weighing AS reputation, prefix specificity, RPKI validity, and volumetric NetFlow deviations.
                  </p>
                  <div style={styles.probGrid}>
                    {Object.entries(dossier.intent_probabilities).map(([intent, prob]) => {
                      const isPrimary = intent === dossier.primary_intent;
                      return (
                        <div key={intent} style={{ ...styles.probCard, ...(isPrimary ? styles.probCardActive : {}) }}>
                          <div style={styles.probHeader}>
                            <span style={{ fontWeight: isPrimary ? 'bold' : 'normal', color: isPrimary ? '#fff' : '#ccd6f6' }}>
                              {formatIntentName(intent)}
                            </span>
                            <span style={{ ...styles.probValue, color: isPrimary ? '#00ffcc' : '#8892b0' }}>
                              {prob}%
                            </span>
                          </div>
                          <div style={styles.progressBarBg}>
                            <div
                              style={{
                                ...styles.progressBarFill,
                                width: `${prob}%`,
                                backgroundColor: isPrimary ? '#00ffcc' : '#334155'
                              }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Tab 2: MITRE ATT&CK Matrix */}
              {activeTab === 'mitre' && (
                <div>
                  <h4 style={styles.sectionHeading}>MITRE ATT&CK for Enterprise Mapping</h4>
                  <p style={styles.sectionDesc}>
                    Tactics, techniques, and procedures (TTPs) mapped to standard cyber threat intelligence taxonomies.
                  </p>
                  <div style={styles.mitreGrid}>
                    {dossier.mitre_attack_matrix.map((item, idx) => (
                      <div key={idx} style={styles.mitreCard}>
                        <div style={styles.mitreHeader}>
                          <span style={styles.mitreId}>{item.technique_id}</span>
                          <span style={styles.mitreTactic}>{item.tactic}</span>
                        </div>
                        <div style={styles.mitreName}>{item.technique_name}</div>
                        <p style={styles.mitreDesc}>{item.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 3: Forensic Evidence */}
              {activeTab === 'evidence' && (
                <div>
                  <h4 style={styles.sectionHeading}>Correlated Threat Evidence Chain</h4>
                  <p style={styles.sectionDesc}>
                    Anomalies and telemetry indicators observed across BGP update streams and NetFlow traffic.
                  </p>
                  <div style={styles.evidenceList}>
                    {dossier.forensic_evidence.map((ev, idx) => (
                      <div key={idx} style={styles.evidenceCard}>
                        <div style={styles.evidenceTop}>
                          <span style={styles.evidenceCategory}>{ev.category}</span>
                          <span style={{
                            ...styles.evidenceSeverity,
                            color: ev.severity === 'CRITICAL' ? '#ff3366' : '#f59e0b',
                            borderColor: ev.severity === 'CRITICAL' ? 'rgba(255, 51, 102, 0.4)' : 'rgba(245, 158, 11, 0.4)'
                          }}>
                            {ev.severity}
                          </span>
                        </div>
                        <div style={styles.evidenceIndicator}>{ev.indicator}</div>
                        <div style={styles.evidenceDetail}>{ev.detail}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 4: Strategic Countermeasures */}
              {activeTab === 'countermeasures' && (
                <div>
                  <h4 style={styles.sectionHeading}>Recommended Tactical Containment Playbook</h4>
                  <p style={styles.sectionDesc}>
                    Prioritized operational actions to neutralize routing deviation and safeguard victim infrastructure.
                  </p>
                  <div style={styles.countermeasureList}>
                    {dossier.strategic_countermeasures.map((cm, idx) => (
                      <div key={idx} style={styles.cmCard}>
                        <div style={styles.cmTop}>
                          <span style={styles.cmStep}>{cm.step}</span>
                          <span style={{
                            ...styles.cmUrgency,
                            background: cm.urgency === 'IMMEDIATE' ? 'rgba(255, 51, 102, 0.2)' : 'rgba(0, 112, 243, 0.2)',
                            color: cm.urgency === 'IMMEDIATE' ? '#ff3366' : '#0070f3'
                          }}>
                            {cm.urgency}
                          </span>
                        </div>
                        <div style={styles.cmAction}>{cm.action}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const styles = {
  overlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(5, 8, 15, 0.85)',
    backdropFilter: 'blur(8px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 2100,
    padding: '20px'
  },
  modal: {
    backgroundColor: '#0a0e17',
    border: '1px solid rgba(0, 255, 204, 0.25)',
    borderRadius: '12px',
    width: '100%',
    maxWidth: '920px',
    maxHeight: '90vh',
    display: 'flex',
    flexDirection: 'column',
    boxShadow: '0 20px 60px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 255, 204, 0.1)',
    overflow: 'hidden'
  },
  header: {
    padding: '24px 28px 18px',
    borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    backgroundColor: 'rgba(15, 23, 42, 0.6)'
  },
  badgeRow: {
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
    marginBottom: '8px'
  },
  intelBadge: {
    fontSize: '11px',
    fontWeight: 'bold',
    letterSpacing: '1.2px',
    padding: '3px 8px',
    borderRadius: '4px',
    background: 'rgba(0, 255, 204, 0.15)',
    color: '#00ffcc',
    border: '1px solid rgba(0, 255, 204, 0.3)',
    fontFamily: 'monospace'
  },
  incidentTag: {
    fontSize: '11px',
    fontFamily: 'monospace',
    padding: '3px 8px',
    borderRadius: '4px',
    background: 'rgba(255, 255, 255, 0.06)',
    color: '#94a3b8'
  },
  title: {
    margin: '0 0 6px 0',
    fontSize: '20px',
    fontWeight: '700',
    color: '#f8fafc',
    letterSpacing: '-0.3px'
  },
  subtitle: {
    fontSize: '13px',
    color: '#94a3b8'
  },
  highlight: {
    color: '#00ffcc',
    fontWeight: '600',
    fontFamily: 'monospace'
  },
  closeBtn: {
    background: 'transparent',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    color: '#94a3b8',
    fontSize: '16px',
    cursor: 'pointer',
    width: '32px',
    height: '32px',
    borderRadius: '6px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.2s ease'
  },
  loadingContainer: {
    padding: '60px 20px',
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center'
  },
  spinner: {
    width: '36px',
    height: '36px',
    border: '3px solid rgba(0, 255, 204, 0.1)',
    borderTop: '3px solid #00ffcc',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite'
  },
  content: {
    padding: '24px 28px',
    overflowY: 'auto',
    flex: 1
  },
  bannerGrid: {
    display: 'grid',
    gridTemplateColumns: '180px 1fr 1fr',
    gap: '16px',
    marginBottom: '24px'
  },
  scoreCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.8)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '8px',
    padding: '16px',
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    alignItems: 'center'
  },
  cardLabel: {
    fontSize: '11px',
    color: '#64748b',
    fontWeight: '700',
    letterSpacing: '0.8px',
    marginBottom: '8px'
  },
  scoreValue: {
    fontSize: '36px',
    fontWeight: '800',
    lineHeight: '1',
    fontFamily: 'monospace'
  },
  scoreMax: {
    fontSize: '16px',
    color: '#64748b',
    fontWeight: 'normal'
  },
  ratingTag: {
    marginTop: '8px',
    fontSize: '11px',
    fontWeight: 'bold',
    border: '1px solid',
    borderRadius: '4px',
    padding: '2px 8px',
    fontFamily: 'monospace'
  },
  attributionCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.8)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '8px',
    padding: '16px',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between'
  },
  intentBadge: {
    fontSize: '14px',
    fontWeight: '700',
    padding: '8px 12px',
    borderRadius: '6px',
    textAlign: 'center',
    letterSpacing: '0.5px'
  },
  confidenceBarContainer: {
    marginTop: '12px'
  },
  confidenceLabel: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '12px',
    color: '#94a3b8',
    marginBottom: '6px'
  },
  progressBarBg: {
    height: '6px',
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderRadius: '3px',
    overflow: 'hidden'
  },
  progressBarFill: {
    height: '100%',
    borderRadius: '3px',
    transition: 'width 0.6s cubic-bezier(0.4, 0, 0.2, 1)'
  },
  telemetryCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.8)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '8px',
    padding: '16px'
  },
  vectorList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    marginTop: '4px'
  },
  vectorItem: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '12px'
  },
  vectorKey: {
    color: '#94a3b8'
  },
  tabBar: {
    display: 'flex',
    gap: '8px',
    borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
    paddingBottom: '12px',
    marginBottom: '20px'
  },
  tabBtn: {
    background: 'transparent',
    border: '1px solid transparent',
    color: '#94a3b8',
    padding: '8px 14px',
    borderRadius: '6px',
    fontSize: '13px',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'all 0.2s ease'
  },
  tabBtnActive: {
    background: 'rgba(0, 255, 204, 0.1)',
    color: '#00ffcc',
    borderColor: 'rgba(0, 255, 204, 0.3)'
  },
  tabContent: {
    minHeight: '260px'
  },
  sectionHeading: {
    margin: '0 0 4px 0',
    fontSize: '15px',
    fontWeight: '600',
    color: '#f8fafc'
  },
  sectionDesc: {
    margin: '0 0 16px 0',
    fontSize: '12px',
    color: '#64748b'
  },
  probGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '12px'
  },
  probCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.5)',
    border: '1px solid rgba(255, 255, 255, 0.06)',
    borderRadius: '8px',
    padding: '12px 14px'
  },
  probCardActive: {
    borderColor: 'rgba(0, 255, 204, 0.4)',
    backgroundColor: 'rgba(0, 255, 204, 0.04)'
  },
  probHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '12px',
    marginBottom: '8px'
  },
  probValue: {
    fontFamily: 'monospace',
    fontWeight: 'bold'
  },
  mitreGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: '14px'
  },
  mitreCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.6)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '8px',
    padding: '16px'
  },
  mitreHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '8px'
  },
  mitreId: {
    fontFamily: 'monospace',
    fontWeight: 'bold',
    fontSize: '12px',
    color: '#ff3366',
    background: 'rgba(255, 51, 102, 0.1)',
    padding: '2px 6px',
    borderRadius: '4px'
  },
  mitreTactic: {
    fontSize: '11px',
    color: '#94a3b8'
  },
  mitreName: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#f8fafc',
    marginBottom: '6px'
  },
  mitreDesc: {
    margin: 0,
    fontSize: '12px',
    color: '#94a3b8',
    lineHeight: '1.4'
  },
  evidenceList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  evidenceCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.6)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '8px',
    padding: '14px 16px'
  },
  evidenceTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '6px'
  },
  evidenceCategory: {
    fontSize: '11px',
    fontWeight: 'bold',
    color: '#00ffcc',
    fontFamily: 'monospace'
  },
  evidenceSeverity: {
    fontSize: '10px',
    fontWeight: 'bold',
    border: '1px solid',
    borderRadius: '3px',
    padding: '1px 6px',
    fontFamily: 'monospace'
  },
  evidenceIndicator: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#f8fafc',
    marginBottom: '4px'
  },
  evidenceDetail: {
    fontSize: '12px',
    color: '#94a3b8',
    lineHeight: '1.4'
  },
  countermeasureList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  cmCard: {
    backgroundColor: 'rgba(15, 23, 42, 0.6)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '8px',
    padding: '14px 16px'
  },
  cmTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '6px'
  },
  cmStep: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#f8fafc'
  },
  cmUrgency: {
    fontSize: '10px',
    fontWeight: 'bold',
    padding: '2px 8px',
    borderRadius: '4px',
    fontFamily: 'monospace'
  },
  cmAction: {
    fontSize: '12px',
    color: '#94a3b8',
    lineHeight: '1.4'
  }
};
