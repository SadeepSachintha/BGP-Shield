import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Radio,
  Activity,
  Network,
  Zap,
  Terminal,
  Settings,
  Flame,
  Globe,
  RefreshCw,
  Cpu,
  History
} from 'lucide-react';

import TopologyGraph from './components/TopologyGraph';
import LiveRadarFeed from './components/LiveRadarFeed';
import ForensicDiffModal from './components/ForensicDiffModal';
import NetFlowTelemetry from './components/NetFlowTelemetry';
import MitigationConsole from './components/MitigationConsole';
import ChaosSimulator from './components/ChaosSimulator';
import PolicySettings from './components/PolicySettings';
import TimeTravelScrubber from './components/TimeTravelScrubber';
import PostMortemModal from './components/PostMortemModal';
import AsnIntelligenceDrawer from './components/AsnIntelligenceDrawer';
import ThreatDossierModal from './components/ThreatDossierModal';
import HistoricalReplayModal from './components/HistoricalReplayModal';

import {
  fetchStatus,
  fetchRecentEvents,
  fetchTopology,
  fetchNetFlow,
  fetchRpkiStatus,
  triggerRpkiSync,
  fetchTimeTravelSnapshots,
  injectTestNetFlow,
  connectBgpWebSocket
} from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('radar'); // radar | netflow | mitigation | chaos | policies
  const [engineStatus, setEngineStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [topology, setTopology] = useState({ nodes: [], links: [] });
  const [netflowData, setNetflowData] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [selectedAsn, setSelectedAsn] = useState(null);
  const [mitigationParams, setMitigationParams] = useState(null);
  const [postMortemIncident, setPostMortemIncident] = useState(null);
  const [threatDossierIncident, setThreatDossierIncident] = useState(null);
  const [showHistoricalModal, setShowHistoricalModal] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [rpkiStatus, setRpkiStatus] = useState(null);
  const [timeTravelSnapshots, setTimeTravelSnapshots] = useState(null);
  const [activePlaybackStep, setActivePlaybackStep] = useState(null);
  const [showTimeTravel, setShowTimeTravel] = useState(true);



  // Initial Data Fetch
  const loadInitialData = async () => {
    try {
      const [statusRes, eventsRes, topoRes, netflowRes, rpkiRes, snapshotsRes] = await Promise.all([
        fetchStatus().catch(() => null),
        fetchRecentEvents(40).catch(() => []),
        fetchTopology().catch(() => ({ nodes: [], links: [] })),
        fetchNetFlow().catch(() => null),
        fetchRpkiStatus().catch(() => null),
        fetchTimeTravelSnapshots().catch(() => null),
      ]);

      if (statusRes) setEngineStatus(statusRes);
      if (eventsRes) setEvents(eventsRes);
      if (topoRes) setTopology(topoRes);
      if (netflowRes) setNetflowData(netflowRes);
      if (rpkiRes) setRpkiStatus(rpkiRes);
      if (snapshotsRes) {
        setTimeTravelSnapshots(snapshotsRes);
        if (snapshotsRes.steps && snapshotsRes.steps[0]) {
          setActivePlaybackStep(snapshotsRes.steps[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load initial data', err);
    }
  };

  const handleSyncRpki = async () => {
    try {
      const res = await triggerRpkiSync();
      if (res && res.status === 'SUCCESS') {
        setRpkiStatus(res);
      }
    } catch (err) {
      console.error('Failed to sync RPKI', err);
    }
  };

  useEffect(() => {
    loadInitialData();

    // Connect WebSocket
    const cleanupWs = connectBgpWebSocket(
      (incomingEvent) => {
        if (incomingEvent.prefix) {
          setEvents((prev) => [incomingEvent, ...prev.slice(0, 99)]);
        }
        // If incident alert, refresh topology and netflow
        if (incomingEvent.is_threat || incomingEvent.type === 'INCIDENT_ALERT') {
          fetchTopology().then(setTopology).catch(() => {});
          fetchNetFlow().then(setNetflowData).catch(() => {});
          fetchStatus().then(setEngineStatus).catch(() => {});
        }
      },
      () => setWsConnected(true),
      () => setWsConnected(false)
    );

    // Periodic telemetry refresh
    const pollInterval = setInterval(() => {
      fetchStatus().then(setEngineStatus).catch(() => {});
      fetchNetFlow().then(setNetflowData).catch(() => {});
    }, 5000);

    return () => {
      cleanupWs();
      clearInterval(pollInterval);
    };
  }, []);

  const activeThreats = events.filter(
    (e) => e.is_hijack || e.is_leak || e.severity === 'CRITICAL' || e.severity === 'HIGH'
  );

  const handleGenerateMitigation = (prefix, rogueAsn, incidentType) => {
    setMitigationParams({ prefix, rogueAsn, incidentType });
    setActiveTab('mitigation');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-black">
      {/* Top Cyber Command Header */}
      <header className="sticky top-0 z-30 bg-slate-950/80 backdrop-blur-xl border-b border-cyan-500/20 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Logo */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-extrabold font-display tracking-tight text-white glow-cyan">
                BGP-SHIELD
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                SENTINEL v1.0
              </span>
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Cyber Threat Intelligence & Route Leak Sentinel
            </p>
          </div>
        </div>

        {/* Live HUD Counters */}
        <div className="flex items-center gap-4 text-xs font-mono">
          {/* Live Feed Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800">
            <span
              className={`w-2 h-2 rounded-full ${
                wsConnected ? 'bg-emerald-400 shadow-[0_0_8px_#10b981]' : 'bg-amber-400 animate-ping'
              }`}
            ></span>
            <span className="text-slate-300">
              {wsConnected ? 'RIPE RIS WebSocket: LIVE' : 'Feed Connecting...'}
            </span>
          </div>

          {/* Messages Processed */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Updates:</span>
            <span className="text-cyan-300 font-bold">
              {engineStatus?.messages_processed?.toLocaleString() || events.length}
            </span>
          </div>

          {/* Live RPKI ROA Sync */}
          <button
            onClick={handleSyncRpki}
            title="Click to trigger live RPKI ROA sync from Cloudflare"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-850 border border-slate-800 text-xs font-mono transition-colors cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">RPKI:</span>
            <span className="font-bold text-emerald-300">
              {rpkiStatus?.total_roas ? `${(rpkiStatus.total_roas / 1000).toFixed(0)}k+ ROAs` : 'Live Sync'}
            </span>
          </button>

          {/* Active Threats */}
          <div
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${
              activeThreats.length > 0
                ? 'bg-red-950/40 border-red-500/50 text-red-300 animate-pulse'
                : 'bg-slate-900/80 border-slate-800 text-slate-400'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>Threats:</span>
            <span className="font-bold text-red-400">{activeThreats.length}</span>
          </div>
        </div>
      </header>

      {/* Navigation Sub-Bar */}
      <div className="bg-slate-950/90 border-b border-slate-800/80 px-6 py-2 flex items-center justify-between overflow-x-auto">
        <nav className="flex items-center gap-1.5 text-xs font-mono">
          <button
            onClick={() => setActiveTab('radar')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'radar'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            Topology & Live Radar
          </button>

          <button
            onClick={() => setActiveTab('netflow')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'netflow'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            NetFlow & DDoS Telemetry
          </button>

          <button
            onClick={() => setActiveTab('mitigation')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'mitigation'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Mitigation Playbooks
          </button>

          <button
            onClick={() => setActiveTab('chaos')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'chaos'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold shadow-[0_0_12px_rgba(245,158,11,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Flame className="w-3.5 h-3.5" />
            Chaos Lab
          </button>

          <button
            onClick={() => setActiveTab('policies')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'policies'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <Settings className="w-3.5 h-3.5" />
            Alert Policies
          </button>

          {/* Historical Disasters Archive */}
          <button
            onClick={() => setShowHistoricalModal(true)}
            title="Browse and replay famous real-world BGP outages & hijacks"
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg transition-all text-purple-300 bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 font-bold shadow-[0_0_12px_rgba(168,85,247,0.15)] cursor-pointer"
          >
            <History className="w-3.5 h-3.5" />
            Historical Archive
          </button>
        </nav>

        <button
          onClick={loadInitialData}
          title="Refresh All Telemetry"
          className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Main Workspace */}
      <main className="flex-1 p-6 max-w-[1600px] w-full mx-auto">
        {/* TAB 1: Topology & Live Radar (Split Screen with Time-Travel) */}
        {activeTab === 'radar' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-[680px]">
            {/* Left: D3.js Force-Directed Graph + Time-Travel Scrubber */}
            <div className="lg:col-span-8 flex flex-col gap-4">
              <div className="h-[480px]">
                <TopologyGraph
                  topologyData={topology}
                  activePlaybackStep={activePlaybackStep}
                  onSelectAsn={(node) => {
                    const raw = node?.asn || (typeof node?.id === 'string' ? node.id.replace('AS', '') : node?.id);
                    const parsed = parseInt(raw);
                    if (!isNaN(parsed)) {
                      setSelectedAsn(parsed);
                    }
                  }}
                />
              </div>

              {showTimeTravel && (
                <TimeTravelScrubber
                  snapshots={timeTravelSnapshots}
                  onStepChange={(step) => setActivePlaybackStep(step)}
                />
              )}
            </div>

            {/* Right: Real-time BGP Announcement Feed */}
            <div className="lg:col-span-4 h-full min-h-[580px]">
              <LiveRadarFeed
                events={events}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
            </div>
          </div>
        )}

        {/* TAB 2: NetFlow & DDoS Telemetry */}
        {activeTab === 'netflow' && <NetFlowTelemetry netflowData={netflowData} />}

        {/* TAB 3: Mitigation Playbooks */}
        {activeTab === 'mitigation' && (
          <MitigationConsole
            initialPrefix={mitigationParams?.prefix || '208.67.222.0/25'}
            initialAsn={mitigationParams?.rogueAsn || 4761}
            initialType={mitigationParams?.incidentType || 'SUBPREFIX_HIJACK'}
            onOpenPostMortem={setPostMortemIncident}
          />
        )}

        {/* TAB 4: Chaos Lab */}
        {activeTab === 'chaos' && (
          <ChaosSimulator
            onScenarioTriggered={(res) => {
              loadInitialData();
            }}
          />
        )}

        {/* TAB 5: Alert Policies */}
        {activeTab === 'policies' && <PolicySettings />}
      </main>

      {/* Forensic Diff Modal */}
      {selectedEvent && (
        <ForensicDiffModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onGenerateMitigation={handleGenerateMitigation}
          onOpenPostMortem={setPostMortemIncident}
          onOpenThreatDossier={setThreatDossierIncident}
        />
      )}

      {/* Post-Mortem Report Modal */}
      {postMortemIncident && (
        <PostMortemModal
          incident={postMortemIncident}
          onClose={() => setPostMortemIncident(null)}
        />
      )}

      {/* ASN PeeringDB Intelligence Drawer */}
      {selectedAsn && (
        <AsnIntelligenceDrawer
          asn={selectedAsn}
          onClose={() => setSelectedAsn(null)}
        />
      )}

      {/* AI Threat Intelligence Dossier Modal */}
      {threatDossierIncident && (
        <ThreatDossierModal
          incident={threatDossierIncident}
          onClose={() => setThreatDossierIncident(null)}
        />
      )}

      {/* Historical Internet Incident Replayer Modal */}
      <HistoricalReplayModal
        isOpen={showHistoricalModal}
        onClose={() => setShowHistoricalModal(false)}
        onIncidentReplayed={(inc) => {
          loadInitialData();
          setThreatDossierIncident(inc);
        }}
      />
    </div>
  );
}


