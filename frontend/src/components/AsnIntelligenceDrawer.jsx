import React, { useState, useEffect } from 'react';
import { fetchAsnPeeringDb } from '../services/api';

export default function AsnIntelligenceDrawer({ asn, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    if (!asn) return;

    const loadData = async () => {
      try {
        setLoading(true);
        const res = await fetchAsnPeeringDb(asn);
        if (isMounted && res) {
          setData(res);
        }
      } catch (err) {
        console.error(`Failed to fetch PeeringDB data for AS${asn}`, err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadData();
    return () => { isMounted = false; };
  }, [asn]);

  if (!asn) return null;

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.drawer} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={styles.header}>
          <div>
            <div style={styles.titleRow}>
              <span style={styles.asnPill}>AS{asn}</span>
              {data && (
                <span style={styles.policyBadge(data.policy_general)}>
                  {data.policy_general} Peering
                </span>
              )}
            </div>
            <h2 style={styles.orgName}>{data?.org_name || `Autonomous System ${asn}`}</h2>
            <div style={styles.infoType}>{data?.info_type || 'Internet Service Provider'}</div>
          </div>
          <button style={styles.closeBtn} onClick={onClose} title="Close">✕</button>
        </div>

        {/* Content */}
        <div style={styles.content}>
          {loading ? (
            <div style={styles.loading}>
              <div style={styles.spinner}></div>
              <p>Querying PeeringDB interconnection directory for AS{asn}...</p>
            </div>
          ) : data ? (
            <div>
              {/* Metric Cards */}
              <div style={styles.grid}>
                <div style={styles.metricCard}>
                  <div style={styles.metricLabel}>PUBLIC PEERING CAPACITY</div>
                  <div style={styles.metricValCyan}>{data.public_peering_capacity}</div>
                  <div style={styles.metricSub}>Port speed / aggregate</div>
                </div>
                <div style={styles.metricCard}>
                  <div style={styles.metricLabel}>DATACENTER FACILITIES</div>
                  <div style={styles.metricValGreen}>{data.fac_count}</div>
                  <div style={styles.metricSub}>Colocation sites</div>
                </div>
                <div style={styles.metricCard}>
                  <div style={styles.metricLabel}>IXP INTERCONNECTIONS</div>
                  <div style={styles.metricValPurple}>{data.ix_count}</div>
                  <div style={styles.metricSub}>Exchange points</div>
                </div>
                <div style={styles.metricCard}>
                  <div style={styles.metricLabel}>TRAFFIC PROFILE</div>
                  <div style={styles.metricValOrange}>{data.traffic_profile}</div>
                  <div style={styles.metricSub}>Ratio: Inbound/Outbound</div>
                </div>
              </div>

              {/* IXP Presence List */}
              <div style={styles.card}>
                <h3 style={styles.cardTitle}>🌐 Major Internet Exchange Points (IXPs)</h3>
                <div style={styles.ixpList}>
                  {data.ixp_presences && data.ixp_presences.length > 0 ? (
                    data.ixp_presences.map((ixp, i) => (
                      <span key={i} style={styles.ixpBadge}>{ixp}</span>
                    ))
                  ) : (
                    <span style={styles.muted}>No public IXP presences listed</span>
                  )}
                </div>
              </div>

              {/* Routing Policy Details */}
              <div style={styles.card}>
                <h3 style={styles.cardTitle}>📜 Peering & Routing Policy</h3>
                <table style={styles.table}>
                  <tbody>
                    <tr style={styles.tr}>
                      <td style={styles.tdLabel}>General Policy:</td>
                      <td style={styles.tdVal}><strong>{data.policy_general}</strong></td>
                    </tr>
                    <tr style={styles.tr}>
                      <td style={styles.tdLabel}>IRR AS-SET:</td>
                      <td style={styles.tdVal}><code>{data.irr_as_set}</code></td>
                    </tr>
                    <tr style={styles.tr}>
                      <td style={styles.tdLabel}>Data Source:</td>
                      <td style={styles.tdVal}><span style={styles.cyan}>{data.source}</span></td>
                    </tr>
                    {data.website && (
                      <tr style={styles.tr}>
                        <td style={styles.tdLabel}>Website:</td>
                        <td style={styles.tdVal}>
                          <a href={data.website} target="_blank" rel="noopener noreferrer" style={styles.link}>
                            {data.website}
                          </a>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Footer link to PeeringDB */}
              <div style={styles.footerLinkContainer}>
                <a
                  href={`https://www.peeringdb.com/asn/${asn}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={styles.peeringDbLink}
                >
                  🔗 View Full PeeringDB Entry for AS{asn} &rarr;
                </a>
              </div>
            </div>
          ) : (
            <div style={styles.error}>No PeeringDB intelligence available for this ASN.</div>
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
    backgroundColor: 'rgba(5, 8, 16, 0.65)',
    backdropFilter: 'blur(4px)',
    display: 'flex',
    justifyContent: 'flex-end',
    zIndex: 1100
  },
  drawer: {
    width: '100%',
    maxWidth: '460px',
    height: '100%',
    backgroundColor: '#0a0f1d',
    borderLeft: '1px solid #1e2d4d',
    boxShadow: '-10px 0 30px rgba(0, 0, 0, 0.7)',
    display: 'flex',
    flexDirection: 'column',
    animation: 'slideIn 0.25s ease-out'
  },
  header: {
    padding: '20px 24px',
    borderBottom: '1px solid #1e2d4d',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    backgroundColor: '#070b16'
  },
  titleRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '6px'
  },
  asnPill: {
    backgroundColor: '#0284c7',
    color: '#ffffff',
    padding: '2px 8px',
    borderRadius: '4px',
    fontFamily: 'monospace',
    fontWeight: 'bold',
    fontSize: '12px'
  },
  policyBadge: (policy) => ({
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 'bold',
    backgroundColor: policy === 'Open' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
    color: policy === 'Open' ? '#10b981' : '#f59e0b',
    border: `1px solid ${policy === 'Open' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(245, 158, 11, 0.4)'}`
  }),
  orgName: {
    margin: '4px 0 2px 0',
    fontSize: '17px',
    color: '#e2e8f0',
    fontWeight: 'bold'
  },
  infoType: {
    fontSize: '12px',
    color: '#94a3b8'
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: '#94a3b8',
    fontSize: '18px',
    cursor: 'pointer',
    padding: '4px 8px',
    borderRadius: '4px'
  },
  content: {
    padding: '20px 24px',
    overflowY: 'auto',
    flex: 1
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '10px',
    marginBottom: '20px'
  },
  metricCard: {
    backgroundColor: '#111827',
    border: '1px solid #1f2937',
    borderRadius: '8px',
    padding: '12px'
  },
  metricLabel: {
    fontSize: '10px',
    color: '#9ca3af',
    fontWeight: '600',
    letterSpacing: '0.5px'
  },
  metricValCyan: {
    fontSize: '16px',
    fontWeight: 'bold',
    color: '#38bdf8',
    margin: '4px 0 2px 0'
  },
  metricValGreen: {
    fontSize: '16px',
    fontWeight: 'bold',
    color: '#10b981',
    margin: '4px 0 2px 0'
  },
  metricValPurple: {
    fontSize: '16px',
    fontWeight: 'bold',
    color: '#c084fc',
    margin: '4px 0 2px 0'
  },
  metricValOrange: {
    fontSize: '16px',
    fontWeight: 'bold',
    color: '#fb923c',
    margin: '4px 0 2px 0'
  },
  metricSub: {
    fontSize: '10px',
    color: '#6b7280'
  },
  card: {
    backgroundColor: '#111827',
    border: '1px solid #1f2937',
    borderRadius: '8px',
    padding: '16px',
    marginBottom: '18px'
  },
  cardTitle: {
    margin: '0 0 12px 0',
    fontSize: '13px',
    color: '#38bdf8',
    fontWeight: 'bold',
    textTransform: 'uppercase',
    letterSpacing: '0.5px'
  },
  ixpList: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '6px'
  },
  ixpBadge: {
    backgroundColor: '#082f49',
    color: '#7dd3fc',
    border: '1px solid #0369a1',
    padding: '3px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: '500'
  },
  table: {
    width: '100%',
    fontSize: '12px'
  },
  tr: {
    borderBottom: '1px solid #1f2937'
  },
  tdLabel: {
    padding: '8px 0',
    color: '#9ca3af',
    width: '40%'
  },
  tdVal: {
    padding: '8px 0',
    color: '#e5e7eb'
  },
  link: {
    color: '#38bdf8',
    textDecoration: 'none'
  },
  footerLinkContainer: {
    textAlign: 'center',
    marginTop: '10px',
    paddingTop: '15px',
    borderTop: '1px solid #1f2937'
  },
  peeringDbLink: {
    color: '#38bdf8',
    fontSize: '12px',
    textDecoration: 'none',
    fontWeight: 'bold'
  },
  cyan: { color: '#38bdf8' },
  muted: { color: '#6b7280', fontSize: '11px' },
  loading: {
    textAlign: 'center',
    padding: '40px',
    color: '#94a3b8'
  },
  spinner: {
    width: '28px',
    height: '28px',
    border: '3px solid #1e293b',
    borderTopColor: '#38bdf8',
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
    margin: '0 auto 12px auto'
  },
  error: {
    textAlign: 'center',
    padding: '30px',
    color: '#ef4444',
    fontSize: '13px'
  }
};
