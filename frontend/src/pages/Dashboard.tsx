import React, { useEffect, useState } from 'react';
import { 
  FileText, 
  ShieldAlert, 
  Server, 
  Activity, 
  Flame, 
  Users, 
  ArrowUpRight, 
  Play, 
  CheckCircle2, 
  Zap, 
  Sparkles 
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { Badge } from '../components/common/Badge';
import { DashboardAnalytics, SecurityAlert } from '../types';
import { request } from '../services/api';
import { NavTab } from '../components/common/Sidebar';

interface DashboardProps {
  setActiveTab: (tab: NavTab) => void;
  onSelectAlertForAI?: (alertId: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ setActiveTab, onSelectAlertForAI }) => {
  const [data, setData] = useState<DashboardAnalytics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [simulating, setSimulating] = useState<string | null>(null);

  const fetchDashboard = async () => {
    try {
      const res = await request<DashboardAnalytics>('/analytics/dashboard');
      setData(res);
    } catch (e) {
      console.error('Failed to load dashboard:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
    const interval = setInterval(fetchDashboard, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async (attackType: string) => {
    setSimulating(attackType);
    try {
      await request('/logs/simulate', {
        method: 'POST',
        body: JSON.stringify({ attack_type: attackType })
      });
      await fetchDashboard();
    } catch (e) {
      console.error('Simulation failed:', e);
    } finally {
      setSimulating(null);
    }
  };

  if (isLoading || !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[500px] gap-3">
        <div className="w-8 h-8 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
        <p className="text-xs font-mono text-slate-400">Aggregating SIEM metrics from MongoDB & Neo4j...</p>
      </div>
    );
  }

  const { kpis, top_ips, top_users, top_servers, recent_alerts, timeline } = data;

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* KPI Counters */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Ingested Logs"
          value={kpis.total_logs.toLocaleString()}
          subtitle="Tamper-proof SHA-256 sealed"
          icon={FileText}
          color="cyan"
          trend="+18.4% today"
        />
        <StatCard
          title="Active Security Alerts"
          value={kpis.total_alerts}
          subtitle={`${kpis.by_status?.NEW || 0} require triage`}
          icon={ShieldAlert}
          color="red"
        />
        <StatCard
          title="Critical & High Threats"
          value={kpis.critical_high_alerts}
          subtitle="Priority incident queue"
          icon={Flame}
          color="amber"
        />
        <StatCard
          title="Monitored Server Assets"
          value={kpis.active_servers}
          subtitle="Protected enterprise nodes"
          icon={Server}
          color="emerald"
        />
      </div>

      {/* Live Simulation Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 shadow-lg">
        <div>
          <h4 className="text-sm font-bold text-white flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <span>Interactive Attack Scenario Simulator</span>
          </h4>
          <p className="text-xs text-slate-400 mt-0.5">
            Inject synthetic multi-stage attack traffic to test the 6 heuristic detection rules in real-time.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {[
            { id: 'brute_force', label: 'Brute Force' },
            { id: 'unusual_ip', label: 'Tor / Unusual IP' },
            { id: 'privilege_escalation', label: 'Privilege Esc' },
            { id: 'distributed_brute_force', label: 'Botnet Spray' },
            { id: 'suspicious_patterns', label: 'Lateral Scan' },
            { id: 'off_hours', label: 'Off-Hours Login' }
          ].map((sc) => (
            <button
              key={sc.id}
              onClick={() => handleSimulate(sc.id)}
              disabled={simulating !== null}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 transition flex items-center gap-1.5 disabled:opacity-50"
            >
              <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
              <span>{simulating === sc.id ? 'Simulating...' : sc.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Middle Grid: Severity Distribution & Top Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Alerts by Severity</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">MongoDB Agg</span>
          </div>

          <div className="mt-4 space-y-3">
            {[
              { level: 'CRITICAL', count: kpis.by_severity?.CRITICAL || 0, color: 'bg-rose-500', text: 'text-rose-400' },
              { level: 'HIGH', count: kpis.by_severity?.HIGH || 0, color: 'bg-orange-500', text: 'text-orange-400' },
              { level: 'MEDIUM', count: kpis.by_severity?.MEDIUM || 0, color: 'bg-amber-500', text: 'text-amber-400' },
              { level: 'LOW', count: kpis.by_severity?.LOW || 0, color: 'bg-blue-500', text: 'text-blue-400' }
            ].map((sev) => {
              const total = kpis.total_alerts || 1;
              const pct = Math.round((sev.count / total) * 100);
              return (
                <div key={sev.level} className="space-y-1">
                  <div className="flex justify-between text-xs font-medium">
                    <span className={sev.text}>{sev.level}</span>
                    <span className="text-slate-300 font-mono">{sev.count} ({pct}%)</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div className={`h-full rounded-full ${sev.color}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 flex justify-between text-xs text-slate-400">
            <span>Triage Status:</span>
            <span className="text-emerald-400 font-medium">
              {kpis.by_status?.RESOLVED || 0} Resolved • {kpis.by_status?.INVESTIGATING || 0} In Progress
            </span>
          </div>
        </div>

        {/* Top Suspicious Attacker IPs */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <span>Top Adversary IPs</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">Threat Feed</span>
          </div>

          <div className="mt-4 space-y-2.5">
            {top_ips.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">No malicious IPs detected yet.</p>
            ) : (
              top_ips.map((item, idx) => (
                <div
                  key={item.ip}
                  className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs font-mono font-bold text-slate-500 w-4">#{idx + 1}</span>
                    <span className="text-xs font-mono font-semibold text-rose-400">{item.ip}</span>
                  </div>
                  <span className="text-xs font-mono bg-rose-500/10 text-rose-300 border border-rose-500/20 px-2 py-0.5 rounded-full">
                    {item.count} events
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Most Targeted Users & Servers */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Users className="w-4 h-4 text-amber-400" />
              <span>Targeted Entities</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">Blast Radius</span>
          </div>

          <div className="mt-4 space-y-3">
            <div>
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Target Accounts</p>
              <div className="flex flex-wrap gap-1.5">
                {top_users.map((u) => (
                  <span
                    key={u.user}
                    className="text-xs font-mono px-2.5 py-1 rounded-lg bg-amber-500/10 text-amber-300 border border-amber-500/20 flex items-center gap-1.5"
                  >
                    <span>{u.user}</span>
                    <span className="text-[10px] bg-amber-500/30 px-1 rounded">{u.count}</span>
                  </span>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/60">
              <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Target Servers</p>
              <div className="flex flex-wrap gap-1.5">
                {top_servers.map((s) => (
                  <span
                    key={s.server}
                    className="text-xs font-mono px-2.5 py-1 rounded-lg bg-purple-500/10 text-purple-300 border border-purple-500/20 flex items-center gap-1.5"
                  >
                    <span>{s.server}</span>
                    <span className="text-[10px] bg-purple-500/30 px-1 rounded">{s.count}</span>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>Active Threat Incidents Queue</span>
            </h4>
            <p className="text-xs text-slate-400 mt-0.5">Automated detection engine outputs with recommended mitigations</p>
          </div>
          <button
            onClick={() => setActiveTab('alerts')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 transition"
          >
            <span>View All Alerts ({kpis.total_alerts})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="mt-4 divide-y divide-slate-800/60">
          {recent_alerts.length === 0 ? (
            <p className="text-xs text-slate-500 py-6 text-center">No active alerts recorded.</p>
          ) : (
            recent_alerts.map((alert) => (
              <div key={alert.alert_id} className="py-3.5 flex flex-wrap items-center justify-between gap-4 hover:bg-slate-800/20 px-2 rounded-xl transition">
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2">
                    <Badge variant={alert.severity} size="sm" />
                    <Badge variant={alert.status} size="sm" />
                    <span className="text-xs font-mono font-semibold text-slate-200">{alert.alert_id}</span>
                    <span className="text-xs text-slate-500">•</span>
                    <span className="text-xs text-slate-400 font-mono">{alert.rule_name}</span>
                  </div>
                  <p className="text-sm font-semibold text-white">{alert.title}</p>
                  <p className="text-xs text-slate-400 line-clamp-1">{alert.description}</p>
                </div>

                <div className="flex items-center gap-2">
                  {onSelectAlertForAI && (
                    <button
                      onClick={() => {
                        onSelectAlertForAI(alert.alert_id);
                        setActiveTab('ai');
                      }}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/20 transition flex items-center gap-1.5"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Explain with AI</span>
                    </button>
                  )}
                  <button
                    onClick={() => setActiveTab('alerts')}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
                  >
                    Triage
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
