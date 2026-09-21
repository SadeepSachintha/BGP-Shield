import React, { useState } from 'react';
import { Terminal, Copy, Check, ShieldCheck, ShieldAlert, Cpu, Play } from 'lucide-react';
import { generateMitigation } from '../services/api';

export default function MitigationConsole({ initialPrefix = '208.67.222.0/25', initialAsn = 4761, initialType = 'SUBPREFIX_HIJACK' }) {
  const [prefix, setPrefix] = useState(initialPrefix);
  const [rogueAsn, setRogueAsn] = useState(initialAsn);
  const [incidentType, setIncidentType] = useState(initialType);
  const [playbooks, setPlaybooks] = useState(null);
  const [activeTab, setActiveTab] = useState('junos');
  const [copied, setCopied] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [deployed, setDeployed] = useState(false);

  const handleGenerate = async (e) => {
    if (e) e.preventDefault();
    setDeployed(false);
    try {
      const res = await generateMitigation(prefix, rogueAsn, incidentType);
      if (res && res.playbooks) {
        setPlaybooks(res.playbooks);
      }
    } catch (err) {
      console.error('Failed to generate mitigation', err);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDeploy = () => {
    setDeploying(true);
    setTimeout(() => {
      setDeploying(false);
      setDeployed(true);
    }, 1500);
  };

  return (
    <div className="space-y-6">
      {/* Mitigation Parameter Form */}
      <div className="glass-panel p-5 border border-cyan-500/20">
        <div className="flex items-center gap-2 mb-4">
          <Terminal className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Automated BGP Mitigation & Flowspec Generator
          </h3>
        </div>

        <form onSubmit={handleGenerate} className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Target Prefix</label>
            <input
              type="text"
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              placeholder="e.g. 208.67.222.0/25"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Rogue / Attacker ASN</label>
            <input
              type="number"
              value={rogueAsn}
              onChange={(e) => setRogueAsn(parseInt(e.target.value) || '')}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              placeholder="e.g. 4761"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Incident Type</label>
            <select
              value={incidentType}
              onChange={(e) => setIncidentType(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="SUBPREFIX_HIJACK">Sub-prefix Hijack</option>
              <option value="EXACT_PREFIX_HIJACK">Exact Prefix Hijack</option>
              <option value="ROUTE_LEAK">Gao-Rexford Route Leak</option>
              <option value="DDOS_AMPLIFICATION">DDoS Amplification</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              className="w-full py-2 px-4 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2"
            >
              <Play className="w-3.5 h-3.5 fill-slate-950" />
              Generate Playbook
            </button>
          </div>
        </form>
      </div>

      {/* Generated Script Display */}
      {playbooks && (
        <div className="glass-panel p-5 border border-cyan-500/30">
          <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
            {/* Router Tabs */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab('junos')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors ${
                  activeTab === 'junos'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-900/60'
                }`}
              >
                Juniper Junos (Flowspec)
              </button>
              <button
                onClick={() => setActiveTab('cisco')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors ${
                  activeTab === 'cisco'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-900/60'
                }`}
              >
                Cisco IOS-XR
              </button>
              <button
                onClick={() => setActiveTab('bird')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors ${
                  activeTab === 'bird'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-900/60'
                }`}
              >
                BIRD (RTBH Blackhole)
              </button>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  const content = activeTab === 'junos' ? playbooks.flowspec_junos : (activeTab === 'cisco' ? playbooks.flowspec_cisco : playbooks.rtbh_bird);
                  handleCopy(content);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy Config'}
              </button>

              <button
                onClick={handleDeploy}
                disabled={deploying || deployed}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                  deployed
                    ? 'bg-emerald-600 text-white'
                    : deploying
                    ? 'bg-amber-600 text-white animate-pulse'
                    : 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-900/30'
                }`}
              >
                {deployed ? (
                  <>
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Applied to Perimeter
                  </>
                ) : (
                  <>
                    <Cpu className="w-3.5 h-3.5" />
                    {deploying ? 'Injecting Routes...' : 'Deploy to Edge Routers'}
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Code Viewer */}
          <div className="relative rounded-xl bg-slate-950 p-4 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
            <pre className="whitespace-pre-wrap leading-relaxed">
              {activeTab === 'junos' && playbooks.flowspec_junos}
              {activeTab === 'cisco' && `${playbooks.flowspec_cisco}\n${playbooks.cisco_as_filter}`}
              {activeTab === 'bird' && playbooks.rtbh_bird}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
