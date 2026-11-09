import React, { useEffect, useState } from 'react';
import { ThreatGraphView } from '../components/graph/ThreatGraphView';
import { GraphTopology } from '../types';
import { request } from '../services/api';
import { Flame, Route, Terminal, Shield, RefreshCw } from 'lucide-react';
import { Badge } from '../components/common/Badge';

export const ThreatGraph: React.FC = () => {
  const [topology, setTopology] = useState<GraphTopology>({ nodes: [], edges: [] });
  const [attackers, setAttackers] = useState<any[]>([]);
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadGraphData = async () => {
    setIsLoading(true);
    try {
      const [topoRes, attackersRes, pathsRes] = await Promise.all([
        request<GraphTopology>('/graph/topology?limit=150'),
        request<any[]>('/graph/attackers'),
        request<any[]>('/graph/attack-paths')
      ]);
      setTopology(topoRes);
      setAttackers(attackersRes);
      setAttackPaths(pathsRes);
    } catch (e) {
      console.error('Failed to load graph data:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadGraphData();
  }, []);

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Controls Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span>Neo4j Graph Relationship Intelligence</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Visualizing multi-entity security graphs: IPs, Users, Monitored Servers, Events, and Threat Alerts.
          </p>
        </div>
        <button
          onClick={loadGraphData}
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Reload Topology</span>
        </button>
      </div>

      {/* Main Interactive Force Graph Canvas */}
      {isLoading ? (
        <div className="w-full h-[600px] bg-[#0b0f19] border border-slate-800 rounded-2xl flex flex-col items-center justify-center gap-3">
          <div className="w-8 h-8 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
          <p className="text-xs font-mono text-slate-400">Executing Cypher graph traversals...</p>
        </div>
      ) : (
        <ThreatGraphView topology={topology} onRefresh={loadGraphData} />
      )}

      {/* Bottom Insights: Repeated Attackers & Attack Paths */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Repeated Multi-Target Attackers */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-500" />
              <span>Repeated Attackers (Cypher Pattern)</span>
            </h4>
            <span className="text-[11px] font-mono text-cyan-400">Multi-Entity Blast</span>
          </div>

          <div className="space-y-2.5">
            {attackers.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">No multi-target attackers identified.</p>
            ) : (
              attackers.map((item) => (
                <div
                  key={item.ip}
                  className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl flex items-center justify-between gap-3 text-xs font-mono"
                >
                  <div>
                    <p className="text-rose-400 font-bold">{item.ip}</p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Targeted: {item.users_targeted?.join(', ') || 'Various assets'}
                    </p>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-300 border border-rose-500/20 text-[10px]">
                      {item.alert_count} active alerts
                    </span>
                    <p className="text-[10px] text-slate-500 mt-1">{item.target_count} connected nodes</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Traced Attack Paths */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Route className="w-4 h-4 text-amber-400" />
              <span>Multi-Hop Lateral Ingress Paths</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">Depth: 1-3 Hops</span>
          </div>

          <div className="space-y-2.5">
            {attackPaths.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">No lateral paths detected.</p>
            ) : (
              attackPaths.map((p, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl space-y-1.5 text-xs font-mono"
                >
                  <div className="flex justify-between items-center text-[11px]">
                    <span className="text-rose-400 font-bold">{p.source_ip}</span>
                    <span className="text-purple-400">{p.destination_server}</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-slate-400">
                    {p.path_nodes?.map((nodeStr: string, i: number) => (
                      <React.Fragment key={i}>
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                          {nodeStr}
                        </span>
                        {i < p.path_nodes.length - 1 && <span className="text-cyan-400 font-bold">→</span>}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
