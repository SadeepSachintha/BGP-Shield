import React, { useState } from 'react';
import { Radio, AlertTriangle, ShieldCheck, ShieldAlert, ArrowRight, Filter } from 'lucide-react';

export default function LiveRadarFeed({ events = [], onSelectEvent }) {
  const [filterThreatsOnly, setFilterThreatsOnly] = useState(false);

  const displayedEvents = filterThreatsOnly
    ? events.filter(e => e.is_hijack || e.is_leak || e.severity === 'CRITICAL' || e.severity === 'HIGH')
    : events;

  const renderBadge = (event) => {
    if (event.is_hijack) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
          <ShieldAlert className="w-3 h-3" />
          {event.hijack_type || 'HIJACK'}
        </span>
      );
    }
    if (event.is_leak) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
          <AlertTriangle className="w-3 h-3" />
          ROUTE LEAK
        </span>
      );
    }
    if (event.rpki_status === 'VALID') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          <ShieldCheck className="w-3 h-3" />
          RPKI VALID
        </span>
      );
    }
    if (event.rpki_status?.includes('INVALID')) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/15 text-red-400 border border-red-500/30">
          <ShieldAlert className="w-3 h-3" />
          {event.rpki_status}
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
        {event.event_type || 'UPDATE'}
      </span>
    );
  };

  return (
    <div className="flex flex-col h-full glass-panel border border-cyan-500/20 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-3.5 border-b border-slate-800 bg-slate-900/60">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            Live BGP Telemetry Stream
          </h3>
          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
            {events.length}
          </span>
        </div>

        {/* Filter Toggle */}
        <button
          onClick={() => setFilterThreatsOnly(!filterThreatsOnly)}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono transition-colors ${
            filterThreatsOnly
              ? 'bg-red-500/20 text-red-300 border border-red-500/40'
              : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
          }`}
        >
          <Filter className="w-3 h-3" />
          {filterThreatsOnly ? 'Threats Only' : 'All Updates'}
        </button>
      </div>

      {/* Stream List */}
      <div className="flex-1 overflow-y-auto p-2 space-y-2">
        {displayedEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-xs font-mono">
            <Radio className="w-6 h-6 mb-2 text-slate-600 animate-pulse" />
            Listening to global RIPE RIS feed...
          </div>
        ) : (
          displayedEvents.map((event, idx) => {
            const isThreat = event.is_hijack || event.is_leak || event.severity === 'CRITICAL';
            return (
              <div
                key={event.id || idx}
                onClick={() => onSelectEvent && onSelectEvent(event)}
                className={`p-3 rounded-lg cursor-pointer transition-all border ${
                  isThreat
                    ? 'bg-red-950/30 hover:bg-red-900/40 border-red-500/40 shadow-[0_0_12px_rgba(239,68,68,0.15)]'
                    : 'bg-slate-900/40 hover:bg-slate-850 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {event.prefix}
                    </span>
                    {renderBadge(event)}
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">
                    {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'now'}
                  </span>
                </div>

                {/* AS-Path Traversal */}
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-300 overflow-x-auto pb-0.5">
                  <span className="text-slate-500 text-[10px]">Path:</span>
                  {Array.isArray(event.as_path) ? (
                    event.as_path.map((asn, i) => (
                      <React.Fragment key={i}>
                        <span
                          className={`px-1.5 py-0.5 rounded ${
                            i === event.as_path.length - 1
                              ? isThreat
                                ? 'bg-red-500/30 text-red-200 font-bold border border-red-500/50'
                                : 'bg-emerald-500/20 text-emerald-300'
                              : 'bg-slate-800/80 text-slate-300'
                          }`}
                        >
                          AS{asn}
                        </span>
                        {i < event.as_path.length - 1 && (
                          <ArrowRight className="w-2.5 h-2.5 text-slate-600 shrink-0" />
                        )}
                      </React.Fragment>
                    ))
                  ) : (
                    <span>{event.as_path}</span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
