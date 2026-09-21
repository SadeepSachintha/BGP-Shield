import React, { useState, useEffect } from 'react';
import { Shield, Bell, Plus, Trash2, CheckCircle2, AlertCircle } from 'lucide-react';

export default function PolicySettings() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newPolicy, setNewPolicy] = useState({
    name: '',
    monitored_prefixes: '8.8.8.0/24, 1.1.1.0/24',
    monitored_asns: '15169, 13335',
    severity_threshold: 'HIGH',
    webhook_channel: 'SLACK',
    webhook_url: 'https://hooks.slack.com/services/...'
  });

  useEffect(() => {
    // Initial static/mock or fetch from Laravel
    setPolicies([
      {
        id: 1,
        name: 'Critical Prefix Hijack & Route Leak Guard',
        monitored_prefixes: ['8.8.8.0/24', '1.1.1.0/24', '208.67.222.0/24', '13.32.0.0/15'],
        monitored_asns: [15169, 13335, 36692, 16509],
        severity_threshold: 'HIGH',
        webhook_channel: 'SLACK',
        is_active: true
      },
      {
        id: 2,
        name: 'PagerDuty 24/7 Tier-1 Transit Emergency',
        monitored_prefixes: ['8.8.8.0/24', '1.1.1.0/24'],
        monitored_asns: [15169, 13335],
        severity_threshold: 'CRITICAL',
        webhook_channel: 'PAGERDUTY',
        is_active: true
      }
    ]);
    setLoading(false);
  }, []);

  const handleAddPolicy = (e) => {
    e.preventDefault();
    if (!newPolicy.name) return;

    const p = {
      id: Date.now(),
      name: newPolicy.name,
      monitored_prefixes: newPolicy.monitored_prefixes.split(',').map(s => s.trim()),
      monitored_asns: newPolicy.monitored_asns.split(',').map(s => parseInt(s.trim()) || 0),
      severity_threshold: newPolicy.severity_threshold,
      webhook_channel: newPolicy.webhook_channel,
      is_active: true
    };

    setPolicies([...policies, p]);
    setNewPolicy({
      name: '',
      monitored_prefixes: '',
      monitored_asns: '',
      severity_threshold: 'HIGH',
      webhook_channel: 'SLACK',
      webhook_url: ''
    });
  };

  const handleDelete = (id) => {
    setPolicies(policies.filter(p => p.id !== id));
  };

  return (
    <div className="space-y-6">
      {/* Existing Policies List */}
      <div className="glass-panel p-5 border border-cyan-500/20">
        <div className="flex items-center gap-2 mb-4">
          <Bell className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Subscriber Alert Policies & Webhooks
          </h3>
        </div>

        <div className="space-y-3">
          {policies.map(policy => (
            <div
              key={policy.id}
              className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-sm font-semibold text-white">{policy.name}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    policy.severity_threshold === 'CRITICAL' ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300'
                  }`}>
                    {policy.severity_threshold}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                    {policy.webhook_channel}
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-400 space-y-0.5">
                  <p>
                    <span className="text-slate-500">Watched Prefixes: </span>
                    <span className="text-cyan-300">{policy.monitored_prefixes.join(', ')}</span>
                  </p>
                  <p>
                    <span className="text-slate-500">Watched ASNs: </span>
                    <span className="text-slate-200">{policy.monitored_asns.map(a => `AS${a}`).join(', ')}</span>
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <span className="inline-flex items-center gap-1 text-xs font-mono text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" /> Active
                </span>
                <button
                  onClick={() => handleDelete(policy.id)}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-red-950/40 text-slate-400 hover:text-red-400 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Add New Policy Form */}
      <div className="glass-panel p-5 border border-cyan-500/20">
        <div className="flex items-center gap-2 mb-4">
          <Plus className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white">
            Create New Alert Policy
          </h3>
        </div>

        <form onSubmit={handleAddPolicy} className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Policy Name</label>
            <input
              type="text"
              value={newPolicy.name}
              onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
              placeholder="e.g. Fintech Edge Subprefix Watcher"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Severity Trigger</label>
            <select
              value={newPolicy.severity_threshold}
              onChange={(e) => setNewPolicy({ ...newPolicy, severity_threshold: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Monitored Prefixes (comma-separated)</label>
            <input
              type="text"
              value={newPolicy.monitored_prefixes}
              onChange={(e) => setNewPolicy({ ...newPolicy, monitored_prefixes: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              placeholder="e.g. 192.0.2.0/24, 198.51.100.0/24"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Monitored ASNs (comma-separated)</label>
            <input
              type="text"
              value={newPolicy.monitored_asns}
              onChange={(e) => setNewPolicy({ ...newPolicy, monitored_asns: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              placeholder="e.g. 15169, 13335"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Notification Channel</label>
            <select
              value={newPolicy.webhook_channel}
              onChange={(e) => setNewPolicy({ ...newPolicy, webhook_channel: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="SLACK">Slack Incoming Webhook</option>
              <option value="PAGERDUTY">PagerDuty Events API v2</option>
              <option value="WEBHOOK">Custom HTTPS Webhook</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Webhook Endpoint URL</label>
            <input
              type="url"
              value={newPolicy.webhook_url}
              onChange={(e) => setNewPolicy({ ...newPolicy, webhook_url: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
              placeholder="https://hooks.slack.com/services/..."
            />
          </div>

          <div className="md:col-span-2 pt-2">
            <button
              type="submit"
              className="py-2 px-5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono font-bold text-xs shadow-lg shadow-cyan-500/20 transition-colors"
            >
              Save Policy
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
