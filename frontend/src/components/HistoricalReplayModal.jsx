import React, { useState, useEffect } from 'react';
import { fetchHistoricalIncidents, replayHistoricalIncident } from '../services/api';

export default function HistoricalReplayModal({ isOpen, onClose, onIncidentReplayed }) {
  const [catalog, setCatalog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [replayingKey, setReplayingKey] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  useEffect(() => {
    if (!isOpen) return;
    setLoading(true);
    setSuccessMessage(null);
    fetchHistoricalIncidents()
      .then((data) => {
        setCatalog(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to load historical catalog:', err);
        setLoading(false);
      });
  }, [isOpen]);

  if (!isOpen) return null;

  const handleReplay = async (key, title) => {
    setReplayingKey(key);
    setSuccessMessage(null);
    try {
      const res = await replayHistoricalIncident(key);
      setSuccessMessage(`Successfully injected "${title}" into live stream and database!`);
      if (onIncidentReplayed && res.incident) {
        onIncidentReplayed(res.incident);
      }
    } catch (err) {
      console.error('Error replaying incident:', err);
    } finally {
      setReplayingKey(null);
    }
  };

  const getTypeColor = (type) => {
    switch (type) {
      case 'SUBPREFIX_HIJACK':
        return '#ff3366';
      case 'GAO_REXFORD_LEAK':
        return '#f59e0b';
      case 'DNS_CRYPTO_HIJACK':
        return '#7928ca';
      default:
        return '#00ffcc';
    }
  };

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={styles.header}>
          <div>
            <div style={styles.badgeRow}>
              <span style={styles.archiveBadge}>HISTORICAL ARCHIVE</span>
              <span style={styles.recordCount}>{catalog.length} DOCUMENTED DISASTERS</span>
            </div>
            <h2 style={styles.title}>Internet BGP Disasters & Route Leak Archive</h2>
            <p style={styles.subtitle}>
              Replay infamous real-world control-plane outages, state-sponsored detours, and crypto hijacks directly into BGP-Shield.
            </p>
          </div>
          <button style={styles.closeBtn} onClick={onClose} title="Close Archive">✕</button>
        </div>

        {/* Success Alert Banner */}
        {successMessage && (
          <div style={styles.successBanner}>
            <span style={{ marginRight: '8px' }}>⚡</span>
            <span>{successMessage}</span>
          </div>
        )}

        {/* Content */}
        <div style={styles.content}>
          {loading ? (
            <div style={styles.loadingContainer}>
              <div style={styles.spinner} />
              <div style={{ marginTop: '16px', color: '#8892b0', fontSize: '14px', fontFamily: 'monospace' }}>
                Loading historical incident archives...
              </div>
            </div>
          ) : catalog.length === 0 ? (
            <div style={styles.loadingContainer}>
              <p style={{ color: '#94a3b8' }}>No historical incidents available.</p>
            </div>
          ) : (
            <div style={styles.grid}>
              {catalog.map((item) => {
                const isReplaying = replayingKey === item.key;
                const typeColor = getTypeColor(item.incident_type);

                return (
                  <div key={item.key} style={styles.card}>
                    {/* Card Top */}
                    <div style={styles.cardHeader}>
                      <div style={styles.yearBadge}>{item.year}</div>
                      <div style={{ ...styles.typeBadge, color: typeColor, borderColor: typeColor }}>
                        {item.incident_type.replace(/_/g, ' ')}
                      </div>
                    </div>

                    <h3 style={styles.cardTitle}>{item.title}</h3>

                    {/* Routing Specs */}
                    <div style={styles.specsContainer}>
                      <div style={styles.specRow}>
                        <span style={styles.specLabel}>Target:</span>
                        <span style={styles.specVal}>{item.target_prefix}</span>
                      </div>
                      <div style={styles.specRow}>
                        <span style={styles.specLabel}>Victim:</span>
                        <span style={styles.specVal}>AS{item.victim_asn} ({item.victim_name})</span>
                      </div>
                      <div style={styles.specRow}>
                        <span style={styles.specLabel}>Rogue Actor:</span>
                        <span style={{ ...styles.specVal, color: '#ff3366' }}>
                          AS{item.attacker_asn} ({item.attacker_name})
                        </span>
                      </div>
                      <div style={styles.specRow}>
                        <span style={styles.specLabel}>Traffic Drop:</span>
                        <span style={{ ...styles.specVal, color: '#f59e0b', fontWeight: 'bold' }}>
                          {item.traffic_drop_pct}%
                        </span>
                      </div>
                    </div>

                    {/* Description */}
                    <p style={styles.cardDesc}>{item.description}</p>

                    {/* Real World Impact */}
                    <div style={styles.impactBox}>
                      <span style={styles.impactLabel}>IMPACT:</span> {item.real_world_impact}
                    </div>

                    {/* Footer Action */}
                    <div style={styles.cardFooter}>
                      <button
                        style={{
                          ...styles.replayBtn,
                          opacity: isReplaying ? 0.7 : 1,
                          cursor: isReplaying ? 'not-allowed' : 'pointer'
                        }}
                        disabled={isReplaying}
                        onClick={() => handleReplay(item.key, item.title)}
                      >
                        {isReplaying ? '⏳ Injecting Incident...' : '▶ Replay Incident in Sentinel'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
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
    zIndex: 2000,
    padding: '20px'
  },
  modal: {
    backgroundColor: '#0a0e17',
    border: '1px solid rgba(0, 255, 204, 0.25)',
    borderRadius: '12px',
    width: '100%',
    maxWidth: '1080px',
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
  archiveBadge: {
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
  recordCount: {
    fontSize: '11px',
    fontFamily: 'monospace',
    padding: '3px 8px',
    borderRadius: '4px',
    background: 'rgba(255, 255, 255, 0.06)',
    color: '#94a3b8'
  },
  title: {
    margin: '0 0 6px 0',
    fontSize: '22px',
    fontWeight: '700',
    color: '#f8fafc',
    letterSpacing: '-0.3px'
  },
  subtitle: {
    margin: 0,
    fontSize: '13px',
    color: '#94a3b8',
    maxWidth: '750px',
    lineHeight: '1.4'
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
  successBanner: {
    backgroundColor: 'rgba(0, 255, 204, 0.15)',
    borderBottom: '1px solid rgba(0, 255, 204, 0.3)',
    color: '#00ffcc',
    padding: '10px 28px',
    fontSize: '13px',
    fontWeight: '600',
    display: 'flex',
    alignItems: 'center'
  },
  content: {
    padding: '24px 28px',
    overflowY: 'auto',
    flex: 1
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
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))',
    gap: '20px'
  },
  card: {
    backgroundColor: 'rgba(15, 23, 42, 0.7)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '10px',
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    transition: 'all 0.2s ease'
  },
  cardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '12px'
  },
  yearBadge: {
    fontSize: '12px',
    fontWeight: 'bold',
    fontFamily: 'monospace',
    color: '#94a3b8',
    background: 'rgba(255, 255, 255, 0.06)',
    padding: '2px 8px',
    borderRadius: '4px'
  },
  typeBadge: {
    fontSize: '11px',
    fontWeight: 'bold',
    fontFamily: 'monospace',
    border: '1px solid',
    borderRadius: '4px',
    padding: '2px 8px'
  },
  cardTitle: {
    margin: '0 0 14px 0',
    fontSize: '16px',
    fontWeight: '700',
    color: '#f8fafc',
    lineHeight: '1.3'
  },
  specsContainer: {
    backgroundColor: 'rgba(10, 14, 23, 0.6)',
    borderRadius: '6px',
    padding: '10px 12px',
    marginBottom: '14px',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px'
  },
  specRow: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '12px'
  },
  specLabel: {
    color: '#64748b'
  },
  specVal: {
    fontFamily: 'monospace',
    color: '#ccd6f6',
    fontWeight: '500'
  },
  cardDesc: {
    margin: '0 0 14px 0',
    fontSize: '12.5px',
    color: '#94a3b8',
    lineHeight: '1.5',
    flex: 1
  },
  impactBox: {
    backgroundColor: 'rgba(255, 51, 102, 0.08)',
    border: '1px solid rgba(255, 51, 102, 0.2)',
    borderRadius: '6px',
    padding: '8px 12px',
    fontSize: '11.5px',
    color: '#ff99aa',
    marginBottom: '16px',
    lineHeight: '1.4'
  },
  impactLabel: {
    fontWeight: 'bold',
    color: '#ff3366',
    marginRight: '4px'
  },
  cardFooter: {
    marginTop: 'auto'
  },
  replayBtn: {
    width: '100%',
    padding: '10px 16px',
    backgroundColor: 'rgba(0, 255, 204, 0.1)',
    color: '#00ffcc',
    border: '1px solid rgba(0, 255, 204, 0.3)',
    borderRadius: '6px',
    fontSize: '13px',
    fontWeight: '600',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    transition: 'all 0.2s ease'
  }
};
