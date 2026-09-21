import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, ArrowRight, X, Terminal, Cpu, Network } from 'lucide-react';

export default function ForensicDiffModal({ event, onClose, onGenerateMitigation }) {
  if (!event) return null;

  const isThreat = event.is_hijack || event.is_leak || event.severity === 'CRITICAL' || event.severity === 'HIGH';
  const roa = event.details?.roa_info || {};
  const hijackInfo = event.details?.hijack_info || {};
  const leakInfo = event.details?.leak_info || {};

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-2xl p-6 rounded-2xl glass-panel border border-cyan-500/30 bg-slate-900/95 shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl ${isThreat ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'}`}>
              {isThreat ? <ShieldAlert className="w-5 h-5" /> : <Network className="w-5 h-5" />}
            </div>
            <div>
              <h3 className="text-base font-bold font-display text-white">
                Forensic Route Analysis: {event.prefix}
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Event ID: {event.id} • Detected via RIPE RIS Live
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Threat Banner */}
        {isThreat && (
          <div className="p-3 mb-4 rounded-xl bg-red-950/40 border border-red-500/50 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs">
              <p className="font-bold text-red-300 uppercase tracking-wide">
                {event.hijack_type || event.leak_type || 'Routing Anomaly Detected'}
              </p>
              <p className="text-red-200/90 mt-0.5">
                {hijackInfo.explanation || leakInfo.explanation || 'Unauthorized origin or path deviation observed in global routing stream.'}
              </p>
            </div>
          </div>
        )}

        {/* Path Comparison / Route Diff */}
        <div className="space-y-4 mb-6">
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
              AS-Path Hop Traversal
            </h4>

            {/* Observed Path */}
            <div>
              <span className="text-[11px] font-mono text-slate-400 block mb-1.5">
                Observed Path (Inbound from Peer {event.peer_ip || '198.32.160.1'}):
              </span>
              <div className="flex items-center gap-2 overflow-x-auto pb-1">
                {Array.isArray(event.as_path) && event.as_path.map((asn, idx) => (
                  <React.Fragment key={idx}>
                    <div className={`px-2.5 py-1 rounded-md text-xs font-mono font-semibold ${
                      idx === event.as_path.length - 1 && isThreat
                        ? 'bg-red-500/30 text-red-300 border border-red-500/50 animate-pulse'
                        : 'bg-slate-800 text-cyan-300 border border-slate-700'
                    }`}>
                      AS{asn}
                    </div>
                    {idx < event.as_path.length - 1 && (
                      <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* RPKI ROA Verification */}
            <div className="grid grid-cols-2 gap-3 pt-3 border-t border-slate-800/80 text-xs">
              <div>
                <span className="text-slate-400 block">RPKI ROA Status:</span>
                <span className={`font-mono font-bold ${
                  event.rpki_status === 'VALID' ? 'text-emerald-400' : 'text-red-400'
                }`}>
                  {event.rpki_status || 'UNKNOWN'}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block">Legitimate Origin ASN:</span>
                <span className="font-mono text-slate-200">
                  {roa.asn ? `AS${roa.asn} (${roa.holder})` : 'No ROA Registered'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Actions */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-mono font-semibold text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-750 transition-colors"
          >
            Close
          </button>
          {isThreat && (
            <button
              onClick={() => {
                onClose();
                if (onGenerateMitigation) {
                  onGenerateMitigation(event.prefix, event.origin_asn, event.hijack_type || 'SUBPREFIX_HIJACK');
                }
              }}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold text-white bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 shadow-lg shadow-red-900/40 transition-all"
            >
              <Terminal className="w-3.5 h-3.5" />
              Generate Router Mitigation
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
