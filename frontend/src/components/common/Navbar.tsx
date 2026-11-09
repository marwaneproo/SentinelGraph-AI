import React, { useState, useEffect } from 'react';
import { Bell, Clock, RefreshCw, Zap } from 'lucide-react';
import { NavTab } from './Sidebar';
import { request } from '../../services/api';

interface NavbarProps {
  activeTab: NavTab;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onRefresh, isRefreshing }) => {
  const [currentTime, setCurrentTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const titleMap: Record<NavTab, { title: string; subtitle: string }> = {
    dashboard: { title: 'Security Analytics Dashboard', subtitle: 'Real-time telemetry, KPIs, and attack incident metrics' },
    logs: { title: 'System Logs Explorer', subtitle: 'Search, filter, inspect, and verify SHA-256 tamper-proof log hashes' },
    alerts: { title: 'Threat Alerts Management', subtitle: 'Investigate, triage, and remediate rule-based detections' },
    graph: { title: 'Threat Investigation Graph', subtitle: 'Neo4j Cypher topological blast radius and attacker relationships' },
    ai: { title: 'AI Security Copilot & Assistant', subtitle: 'LLM natural language threat reasoning and MITRE ATT&CK guidance' },
    servers: { title: 'Monitored Server Assets', subtitle: 'Criticality, health status, and log ingestion distribution' },
    rules: { title: 'Detection Engine Rules', subtitle: 'Active heuristic rules, thresholds, and execution telemetry' },
  };

  const handleRunDetection = async () => {
    try {
      await request('/alerts/run-detection', { method: 'POST' });
      if (onRefresh) onRefresh();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <header className="h-16 px-8 border-b border-slate-800 bg-[#090d16]/80 backdrop-blur sticky top-0 z-30 flex items-center justify-between">
      <div>
        <h1 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
          {titleMap[activeTab].title}
        </h1>
        <p className="text-xs text-slate-400">{titleMap[activeTab].subtitle}</p>
      </div>

      <div className="flex items-center gap-3">
        {/* UTC Clock */}
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{currentTime || 'Synchronizing UTC...'}</span>
        </div>

        {/* Run Detection Engine Button */}
        <button
          onClick={handleRunDetection}
          className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/30 transition shadow-sm"
          title="Trigger Threat Detection Pipeline immediately across recent logs"
        >
          <Zap className="w-3.5 h-3.5 text-indigo-400" />
          <span>Run Detector</span>
        </button>

        {/* Refresh Button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-800 transition disabled:opacity-50"
            title="Refresh View"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        )}
      </div>
    </header>
  );
};
