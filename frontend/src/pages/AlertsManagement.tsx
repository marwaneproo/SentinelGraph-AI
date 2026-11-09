import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  CheckCircle, 
  Sparkles, 
  FileText, 
  Clock, 
  UserCheck, 
  Send, 
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  ShieldCheck
} from 'lucide-react';
import { SecurityAlert, AlertListResponse, AIAnalysisReport, SecurityLog } from '../types';
import { request } from '../services/api';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { useAuth } from '../context/AuthContext';

export const AlertsManagement: React.FC = () => {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Modals
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [aiReport, setAiReport] = useState<AIAnalysisReport | null>(null);
  const [isLoadingAI, setIsLoadingAI] = useState(false);
  const [evidenceLogs, setEvidenceLogs] = useState<SecurityLog[]>([]);
  const [isEvidenceOpen, setIsEvidenceOpen] = useState(false);

  // Status update form inside triage
  const [statusNote, setStatusNote] = useState('');
  const [newStatus, setNewStatus] = useState<string>('INVESTIGATING');

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', page.toString());
      params.set('page_size', pageSize.toString());
      if (severity) params.set('severity', severity);
      if (status) params.set('status', status);
      if (search) params.set('search', search);

      const res = await request<AlertListResponse>(`/alerts?${params.toString()}`);
      setAlerts(res.alerts);
      setTotal(res.total);
    } catch (e) {
      console.error('Failed to load alerts:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, severity, status]);

  const handleExplainAI = async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setIsLoadingAI(true);
    try {
      const res = await request<AIAnalysisReport>('/ai/analyze', {
        method: 'POST',
        body: JSON.stringify({ alert_id: alert.alert_id })
      });
      setAiReport(res);
    } catch (e) {
      console.error('AI analysis error:', e);
    } finally {
      setIsLoadingAI(false);
    }
  };

  const handleOpenEvidence = async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    try {
      const res = await request<SecurityLog[]>(`/alerts/${alert.alert_id}/evidence`);
      setEvidenceLogs(res);
      setIsEvidenceOpen(true);
    } catch (e) {
      console.error(e);
    }
  };

  const handleUpdateStatus = async (alertId: string) => {
    try {
      await request(`/alerts/${alertId}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: newStatus,
          investigation_notes: statusNote,
          assigned_to: user?.username || 'analyst'
        })
      });
      setStatusNote('');
      setSelectedAlert(null);
      await fetchAlerts();
    } catch (e) {
      console.error(e);
    }
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Filters Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search alert title, rule, user, or IP..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-10 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>

          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition"
          >
            <option value="">All Statuses</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>

        <button
          onClick={fetchAlerts}
          className="px-4 py-2.5 rounded-xl font-semibold text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
        >
          Refresh Queue
        </button>
      </div>

      {/* Alerts Grid / List */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-12 text-center text-xs text-slate-500">
            <div className="w-6 h-6 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin mx-auto mb-2" />
            Retrieving alerts from MongoDB...
          </div>
        ) : alerts.length === 0 ? (
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-12 text-center text-xs text-slate-500">
            No alerts match current filter criteria.
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.alert_id}
              className="bg-[#0f172a] border border-slate-800/80 hover:border-slate-700 rounded-2xl p-5 shadow-lg transition space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Badge variant={alert.severity} />
                  <Badge variant={alert.status} />
                  <span className="text-xs font-mono font-bold text-white">{alert.alert_id}</span>
                  <span className="text-xs text-slate-500 font-mono">• {alert.rule_name}</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  <span>{alert.timestamp ? alert.timestamp.replace('T', ' ').slice(0, 19) : ''}</span>
                </div>
              </div>

              <div>
                <h3 className="text-base font-bold text-white">{alert.title}</h3>
                <p className="text-xs text-slate-400 mt-1">{alert.description}</p>
              </div>

              {/* Context metadata pill */}
              <div className="flex flex-wrap gap-4 text-xs font-mono p-3 bg-slate-950/60 border border-slate-800/60 rounded-xl">
                <div>
                  <span className="text-slate-500">Attacker IP:</span>{' '}
                  <span className="text-rose-400 font-semibold">{alert.source_ip || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Target User:</span>{' '}
                  <span className="text-amber-400 font-semibold">{alert.target_user || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-500">Affected Server:</span>{' '}
                  <span className="text-purple-400 font-semibold">{alert.server_id || 'N/A'}</span>
                </div>
                {alert.assigned_to && (
                  <div>
                    <span className="text-slate-500">Assigned To:</span>{' '}
                    <span className="text-cyan-400 font-semibold">{alert.assigned_to}</span>
                  </div>
                )}
              </div>

              {/* Recommended Action */}
              <div className="text-xs text-slate-300 bg-slate-900/60 p-3 rounded-xl border border-slate-800/60">
                <span className="text-cyan-400 font-semibold">Recommended Containment: </span>
                {alert.recommended_action}
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExplainAI(alert)}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-500/20 to-indigo-500/20 text-cyan-300 border border-cyan-500/30 hover:border-cyan-500/60 transition flex items-center gap-1.5 shadow-sm"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Explain Threat with AI</span>
                  </button>

                  <button
                    onClick={() => handleOpenEvidence(alert)}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition flex items-center gap-1.5"
                  >
                    <FileText className="w-3.5 h-3.5 text-slate-400" />
                    <span>Evidence Logs ({alert.evidence_log_ids?.length || 0})</span>
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSelectedAlert(alert)}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/30 transition flex items-center gap-1.5"
                  >
                    <UserCheck className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Triage & Update Status</span>
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl px-6 py-4 flex items-center justify-between text-xs text-slate-400 shadow-lg">
        <div>
          Showing Page <span className="font-bold text-white">{page}</span> of <span className="font-bold text-white">{totalPages}</span> ({total} alerts)
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:opacity-40 transition"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:opacity-40 transition"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* AI Threat Explanation Modal */}
      {selectedAlert && (aiReport || isLoadingAI) && (
        <Modal
          isOpen={!!selectedAlert && (!!aiReport || isLoadingAI)}
          onClose={() => {
            setSelectedAlert(null);
            setAiReport(null);
          }}
          title={`AI Security Investigation Report [${selectedAlert.alert_id}]`}
          maxWidth="3xl"
        >
          {isLoadingAI ? (
            <div className="py-12 text-center space-y-3">
              <div className="w-8 h-8 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin mx-auto" />
              <p className="text-xs font-mono text-cyan-400">Synthesizing threat intelligence & MITRE ATT&CK tactics...</p>
            </div>
          ) : aiReport ? (
            <div className="space-y-4 text-xs">
              {/* Model status pill */}
              <div className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span className="font-mono text-slate-300">Model: {aiReport.model_used}</span>
                </div>
                <Badge
                  variant={aiReport.is_fallback ? 'INVESTIGATING' : 'RESOLVED'}
                  label={aiReport.is_fallback ? 'Expert Rules Fallback' : 'Ollama Local LLM'}
                  size="sm"
                />
              </div>

              {/* Executive Summary */}
              <div>
                <h5 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Executive Briefing:
                </h5>
                <p className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-white font-medium text-sm">
                  {aiReport.summary}
                </p>
              </div>

              {/* Threat Explanation */}
              <div>
                <h5 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Adversary TTPs & Forensic Analysis:
                </h5>
                <p className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-slate-300 leading-relaxed">
                  {aiReport.threat_explanation}
                </p>
              </div>

              {/* MITRE ATT&CK */}
              <div>
                <h5 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Mapped MITRE ATT&CK Techniques:
                </h5>
                <div className="flex flex-wrap gap-2">
                  {aiReport.mitre_tactics.map((tac) => (
                    <span
                      key={tac}
                      className="px-2.5 py-1 rounded-lg bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono text-xs"
                    >
                      {tac}
                    </span>
                  ))}
                </div>
              </div>

              {/* Blast Radius Assessment */}
              <div>
                <h5 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Blast Radius & Impact Evaluation:
                </h5>
                <p className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-amber-300">
                  {aiReport.blast_radius_assessment}
                </p>
              </div>

              {/* Concrete Mitigation Steps */}
              <div>
                <h5 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                  Recommended Containment Procedures:
                </h5>
                <ul className="space-y-1.5 p-3 bg-slate-950 rounded-xl border border-slate-800 text-slate-300 list-disc list-inside">
                  {aiReport.recommended_mitigation.map((m, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {m}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-2 text-[10px] text-slate-500 font-mono text-center">
                Guardrail: AI analysis is advisory and supplements forensic evidence hashes without replacing raw log data.
              </div>
            </div>
          ) : null}
        </Modal>
      )}

      {/* Evidence Logs Modal */}
      {isEvidenceOpen && selectedAlert && (
        <Modal
          isOpen={isEvidenceOpen}
          onClose={() => {
            setIsEvidenceOpen(false);
            setSelectedAlert(null);
          }}
          title={`Forensic Evidence Logs [${selectedAlert.alert_id}]`}
          maxWidth="4xl"
        >
          <div className="space-y-3 text-xs">
            <p className="text-slate-400">
              The following raw security telemetry triggered rule{' '}
              <strong className="text-white font-mono">{selectedAlert.rule_id}</strong>:
            </p>
            <div className="space-y-2 max-h-[60vh] overflow-y-auto pr-1">
              {evidenceLogs.length === 0 ? (
                <p className="text-slate-500 py-4 text-center">No raw evidence logs attached.</p>
              ) : (
                evidenceLogs.map((log) => (
                  <div key={log._id || log.integrity_hash} className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>{log.timestamp}</span>
                      <Badge variant={log.severity} size="sm" />
                    </div>
                    <p className="text-white font-sans">{log.message}</p>
                    <div className="text-[10px] text-cyan-400 pt-1 border-t border-slate-800/80 break-all">
                      SHA-256: {log.integrity_hash}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* Triage & Update Modal */}
      {selectedAlert && !aiReport && !isLoadingAI && !isEvidenceOpen && (
        <Modal
          isOpen={!!selectedAlert}
          onClose={() => setSelectedAlert(null)}
          title={`Triage Alert [${selectedAlert.alert_id}]`}
          maxWidth="md"
        >
          <div className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-400 font-semibold mb-1">Set New Status:</label>
              <select
                value={newStatus}
                onChange={(e) => setNewStatus(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="NEW">NEW</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Investigation Notes:</label>
              <textarea
                value={statusNote}
                onChange={(e) => setStatusNote(e.target.value)}
                rows={3}
                placeholder="Document containment action, firewall rule applied, or root cause..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-3.5 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
              >
                Cancel
              </button>
              <button
                onClick={() => handleUpdateStatus(selectedAlert.alert_id)}
                className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition flex items-center gap-1.5"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                <span>Save Status</span>
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
