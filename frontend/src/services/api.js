/**
 * BGP-Shield API & WebSocket Communication Service
 */

const BASE_URL = 'http://127.0.0.1:8000';
const WS_URL = 'ws://127.0.0.1:8000/api/ws/events';

export const fetchStatus = async () => {
  const res = await fetch(`${BASE_URL}/api/status`);
  return res.json();
};

export const fetchRecentEvents = async (limit = 50, threatsOnly = false) => {
  const res = await fetch(`${BASE_URL}/api/events?limit=${limit}&threats_only=${threatsOnly}`);
  return res.json();
};

export const fetchIncidents = async (limit = 20) => {
  const res = await fetch(`${BASE_URL}/api/incidents?limit=${limit}`);
  return res.json();
};

export const fetchTopology = async () => {
  const res = await fetch(`${BASE_URL}/api/topology`);
  return res.json();
};

export const fetchNetFlow = async () => {
  const res = await fetch(`${BASE_URL}/api/netflow`);
  return res.json();
};

export const triggerSimulation = async (scenario) => {
  const res = await fetch(`${BASE_URL}/api/simulate/${scenario}`, {
    method: 'POST',
  });
  return res.json();
};

export const generateMitigation = async (prefix, rogueAsn, incidentType) => {
  const res = await fetch(`${BASE_URL}/api/mitigate?prefix=${encodeURIComponent(prefix)}&rogue_asn=${rogueAsn || 0}&incident_type=${encodeURIComponent(incidentType || 'SUBPREFIX_HIJACK')}`, {
    method: 'POST',
  });
  return res.json();
};

export const fetchRpkiStatus = async () => {
  const res = await fetch(`${BASE_URL}/api/rpki/status`);
  return res.json();
};

export const triggerRpkiSync = async () => {
  const res = await fetch(`${BASE_URL}/api/rpki/sync`, { method: 'POST' });
  return res.json();
};

export const fetchTimeTravelSnapshots = async (incidentId = null) => {
  const url = incidentId ? `${BASE_URL}/api/time-travel/snapshots?incident_id=${incidentId}` : `${BASE_URL}/api/time-travel/snapshots`;
  const res = await fetch(url);
  return res.json();
};

export const injectTestNetFlow = async (count = 3) => {
  const res = await fetch(`${BASE_URL}/api/netflow/inject-test-flows?count=${count}`, { method: 'POST' });
  return res.json();
};

// WebSocket Connector
export const connectBgpWebSocket = (onMessage, onOpen, onClose) => {
  let socket = null;
  let retryTimer = null;

  const connect = () => {
    socket = new WebSocket(WS_URL);

    socket.onopen = () => {
      console.log('[BGP-Shield] WebSocket connected to Sentinel Engine');
      if (onOpen) onOpen();
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (onMessage) onMessage(data);
      } catch (e) {
        console.error('[BGP-Shield] Error parsing WS message', e);
      }
    };

    socket.onclose = () => {
      console.warn('[BGP-Shield] WebSocket closed. Reconnecting in 3s...');
      if (onClose) onClose();
      retryTimer = setTimeout(connect, 3000);
    };

    socket.onerror = (err) => {
      console.error('[BGP-Shield] WebSocket error:', err);
      socket.close();
    };
  };

  connect();

  return () => {
    if (retryTimer) clearTimeout(retryTimer);
    if (socket) socket.close();
  };
};
