import React, { useState } from 'react';
import { Flame, ShieldAlert, AlertTriangle, Zap, Play, CheckCircle2 } from 'lucide-react';
import { triggerSimulation } from '../services/api';

export default function ChaosSimulator({ onScenarioTriggered }) {
  const [loadingScenario, setLoadingScenario] = useState(null);
  const [lastResult, setLastResult] = useState(null);

  const handleTrigger = async (scenarioKey) => {
    setLoadingScenario(scenarioKey);
    setLastResult(null);
    try {
      const res = await triggerSimulation(scenarioKey);
      setLastResult(res);
      if (onScenarioTriggered) {
        onScenarioTriggered(res);
      }
    } catch (err) {
      console.error('Error triggering simulation', err);
    } finally {
      setLoadingScenario(null);
    }
  };

  return (
    <div className="glass-panel p-5 border border-cyan-500/20">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Flame className="w-5 h-5 text-amber-500" />
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Chaos Engineering & BGP Attack Simulator
          </h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Inject synthetic anomalies into the live stream
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Scenario 1 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-red-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-red-400 mb-2">
              <ShieldAlert className="w-4 h-4" />
              <h4 className="font-mono text-xs font-bold uppercase">Sub-prefix Hijack</h4>
            </div>
            <p className="text-xs text-slate-300 mb-2 font-medium">
              DNS Hijack / Traffic Interception
            </p>
            <p className="text-[11px] text-slate-400 mb-3 leading-relaxed">
              Rogue AS4761 announces <code className="text-cyan-300">208.67.222.0/25</code> to hijack Cisco OpenDNS <code className="text-slate-300">208.67.222.0/24</code> via Longest Prefix Match (LPM).
            </p>
          </div>
          <button
            onClick={() => handleTrigger('subprefix_hijack')}
            disabled={loadingScenario === 'subprefix_hijack'}
            className="w-full py-2 px-3 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/40 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Play className="w-3 h-3 fill-current" />
            {loadingScenario === 'subprefix_hijack' ? 'Injecting Attack...' : 'Trigger Hijack'}
          </button>
        </div>

        {/* Scenario 2 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-amber-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-amber-400 mb-2">
              <AlertTriangle className="w-4 h-4" />
              <h4 className="font-mono text-xs font-bold uppercase">Gao-Rexford Route Leak</h4>
            </div>
            <p className="text-xs text-slate-300 mb-2 font-medium">
              Transit Hairpin Leak (RFC 7908)
            </p>
            <p className="text-[11px] text-slate-400 mb-3 leading-relaxed">
              Tier-2 ISP AS37282 leaks Cloudflare <code className="text-cyan-300">1.1.1.0/24</code> learned from Lumen (AS3356) to Cogent (AS174), violating valley-free routing.
            </p>
          </div>
          <button
            onClick={() => handleTrigger('route_leak')}
            disabled={loadingScenario === 'route_leak'}
            className="w-full py-2 px-3 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Play className="w-3 h-3 fill-current" />
            {loadingScenario === 'route_leak' ? 'Injecting Leak...' : 'Trigger Route Leak'}
          </button>
        </div>

        {/* Scenario 3 */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 mb-2">
              <Zap className="w-4 h-4" />
              <h4 className="font-mono text-xs font-bold uppercase">DDoS Amplification</h4>
            </div>
            <p className="text-xs text-slate-300 mb-2 font-medium">
              Memcached & NTP Reflection Flood
            </p>
            <p className="text-[11px] text-slate-400 mb-3 leading-relaxed">
              High-velocity UDP reflection attack targeting <code className="text-cyan-300">8.8.8.0/24</code> with up to 51,000x volumetric payload multiplication.
            </p>
          </div>
          <button
            onClick={() => handleTrigger('ddos_amplification')}
            disabled={loadingScenario === 'ddos_amplification'}
            className="w-full py-2 px-3 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors"
          >
            <Play className="w-3 h-3 fill-current" />
            {loadingScenario === 'ddos_amplification' ? 'Simulating Flood...' : 'Trigger Flood'}
          </button>
        </div>
      </div>

      {/* Execution Feedback */}
      {lastResult && (
        <div className="mt-4 p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 flex items-center gap-2 text-xs font-mono text-emerald-300">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>
            Scenario '{lastResult.scenario}' injected successfully. BGP updates and NetFlow telemetry processed by stream engine!
          </span>
        </div>
      )}
    </div>
  );
}
