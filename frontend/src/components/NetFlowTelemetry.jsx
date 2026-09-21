import React from 'react';
import { Activity, Zap, ShieldAlert, BarChart3, Radio, ArrowDownRight } from 'lucide-react';

export default function NetFlowTelemetry({ netflowData }) {
  const telemetry = netflowData?.telemetry || {};
  const analytics = netflowData?.analytics || {};
  const recentFlows = telemetry.recent_flows || [];
  const protocols = analytics.protocols || [];

  const totalBytes = analytics.total_bytes || telemetry.total_bytes || 0;
  const totalPackets = analytics.total_packets || telemetry.total_packets || 0;
  const ddosEvents = analytics.ddos_events || telemetry.ddos_events_detected || 0;
  const peakAmplification = analytics.peak_amplification || 1.0;

  const totalGb = (totalBytes / (1024 ** 3)).toFixed(2);
  const totalMpkts = (totalPackets / 1000000).toFixed(2);

  return (
    <div className="space-y-6">
      {/* Top Stat Counters */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 border border-cyan-500/20">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">Total Flow Bandwidth</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">
            {totalGb} <span className="text-sm text-cyan-400 font-normal">GB</span>
          </p>
          <span className="text-[10px] font-mono text-slate-500">Columnar DuckDB Ingestion</span>
        </div>

        <div className="glass-panel p-4 border border-cyan-500/20">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">Total Packets Analyzed</span>
            <BarChart3 className="w-4 h-4 text-blue-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">
            {totalMpkts} <span className="text-sm text-blue-400 font-normal">Mpkts</span>
          </p>
          <span className="text-[10px] font-mono text-slate-500">Sub-second aggregate window</span>
        </div>

        <div className="glass-panel p-4 border border-red-500/30 bg-red-950/20">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-red-300">DDoS Reflection Vectors</span>
            <ShieldAlert className="w-4 h-4 text-red-400 animate-pulse" />
          </div>
          <p className="text-2xl font-bold font-mono text-red-400">
            {ddosEvents}
          </p>
          <span className="text-[10px] font-mono text-red-400/80">Amplification Signatures</span>
        </div>

        <div className="glass-panel p-4 border border-amber-500/30 bg-amber-950/20">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-amber-300">Peak Amplification Factor</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-amber-300">
            {peakAmplification.toLocaleString()}x
          </p>
          <span className="text-[10px] font-mono text-amber-400/80">Memcached / NTP Reflection</span>
        </div>
      </div>

      {/* DDoS Vector Breakdown */}
      <div className="glass-panel p-5 border border-cyan-500/20">
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 mb-4 flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          DDoS Volumetric Amplification Vectors
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-xs font-bold text-white">Memcached UDP (Port 11211)</span>
              <span className="text-xs font-mono font-bold text-red-400">51,000x</span>
            </div>
            <p className="text-[11px] text-slate-400">Payload amplification via stats get commands without authentication.</p>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-xs font-bold text-white">NTP Monlist (Port 123)</span>
              <span className="text-xs font-mono font-bold text-amber-400">556.9x</span>
            </div>
            <p className="text-[11px] text-slate-400">Mode 7 monlist responses returning last 600 client addresses.</p>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-xs font-bold text-white">DNS ANY Amplification (Port 53)</span>
              <span className="text-xs font-mono font-bold text-cyan-400">54.0x</span>
            </div>
            <p className="text-[11px] text-slate-400">Open DNS resolver abuse with large EDNS0 responses to spoofed victim IP.</p>
          </div>
        </div>
      </div>

      {/* Recent High-Volume Flow Records */}
      <div className="glass-panel p-5 border border-cyan-500/20">
        <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 mb-4 flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400" />
          Recent NetFlow Records
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-2">Source IP : Port</th>
                <th className="pb-2">Destination IP : Port</th>
                <th className="pb-2">Protocol</th>
                <th className="pb-2">Bandwidth</th>
                <th className="pb-2">Packets</th>
                <th className="pb-2">Vector / Threat</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {recentFlows.length === 0 ? (
                <tr>
                  <td colSpan="6" className="py-4 text-center text-slate-500">
                    No active flow anomalies detected.
                  </td>
                </tr>
              ) : (
                recentFlows.slice(0, 10).map((flow, i) => (
                  <tr key={flow.id || i} className={flow.is_ddos_vector ? 'bg-red-950/20' : ''}>
                    <td className="py-2.5 text-slate-300">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="py-2.5 text-cyan-300">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-2.5 text-slate-400">{flow.protocol}</td>
                    <td className="py-2.5 font-bold text-white">
                      {(flow.bytes / (1024 * 1024)).toFixed(2)} MB
                    </td>
                    <td className="py-2.5 text-slate-300">
                      {flow.packets?.toLocaleString()}
                    </td>
                    <td className="py-2.5">
                      {flow.is_ddos_vector ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                          {flow.vector_type} ({flow.amplification_factor}x)
                        </span>
                      ) : (
                        <span className="text-slate-500">Standard Traffic</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
