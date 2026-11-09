import React, { useState, useEffect } from 'react';
import { Sliders, Shield, Zap, ToggleLeft, ToggleRight, CheckCircle2, Clock } from 'lucide-react';
import { DetectionRule } from '../types';
import { request } from '../services/api';
import { Badge } from '../components/common/Badge';
import { useAuth } from '../context/AuthContext';

export const RulesManagement: React.FC = () => {
  const { hasRole } = useAuth();
  const canModify = hasRole(['Administrator', 'Security Analyst']);

  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchRules = async () => {
    setIsLoading(true);
    try {
      const res = await request<DetectionRule[]>('/rules');
      setRules(res);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (rule: DetectionRule) => {
    if (!canModify) return;
    try {
      await request(`/rules/${rule.rule_id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !rule.enabled })
      });
      await fetchRules();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <span>Threat Detection Rules Engine</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Configurable heuristic correlation rules analyzing log time windows and generating structured incidents.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-3 py-1.5 rounded-xl">
          <Zap className="w-4 h-4" />
          <span>6 SIEM Correlation Rules Active</span>
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-12 text-center text-xs text-slate-500">
            <div className="w-6 h-6 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin mx-auto mb-2" />
            Retrieving detection rules...
          </div>
        ) : (
          rules.map((rule) => (
            <div
              key={rule.rule_id}
              className={`bg-[#0f172a] border rounded-2xl p-5 shadow-lg transition space-y-3 ${
                rule.enabled ? 'border-slate-800 hover:border-slate-700' : 'border-slate-800/40 opacity-60'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <Badge variant={rule.severity} size="sm" />
                  <span className="text-xs font-mono font-bold text-cyan-400">{rule.rule_id}</span>
                  {rule.mitre_attack_id && (
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                      MITRE {rule.mitre_attack_id}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400">
                    Triggers: <strong className="text-white">{rule.trigger_count ?? 0}</strong>
                  </span>

                  {canModify && (
                    <button
                      onClick={() => handleToggle(rule)}
                      className="flex items-center gap-1.5 text-xs font-medium text-slate-300 hover:text-white transition"
                      title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                    >
                      {rule.enabled ? (
                        <ToggleRight className="w-6 h-6 text-emerald-400" />
                      ) : (
                        <ToggleLeft className="w-6 h-6 text-slate-600" />
                      )}
                      <span className="text-[11px]">{rule.enabled ? 'Active' : 'Disabled'}</span>
                    </button>
                  )}
                </div>
              </div>

              <div>
                <h4 className="text-sm font-bold text-white">{rule.name}</h4>
                <p className="text-xs text-slate-400 mt-1">{rule.description}</p>
              </div>

              {/* Threshold & Window specs */}
              <div className="flex flex-wrap items-center gap-4 text-xs font-mono p-3 bg-slate-950/70 border border-slate-800 rounded-xl">
                <div>
                  <span className="text-slate-500">Threshold:</span>{' '}
                  <span className="text-amber-300 font-bold">{rule.threshold} matching events</span>
                </div>
                <div>
                  <span className="text-slate-500">Window:</span>{' '}
                  <span className="text-cyan-300 font-bold">{rule.window_seconds} seconds</span>
                </div>
                {rule.last_triggered && (
                  <div className="ml-auto flex items-center gap-1.5 text-slate-400 text-[11px]">
                    <Clock className="w-3.5 h-3.5" />
                    <span>Last fired: {rule.last_triggered.replace('T', ' ').slice(0, 19)}</span>
                  </div>
                )}
              </div>

              {/* Recommended Action */}
              <div className="text-xs text-slate-300 bg-slate-900/60 p-3 rounded-xl border border-slate-800/60">
                <span className="text-cyan-400 font-semibold">Standard Playbook Action: </span>
                {rule.recommended_action}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
