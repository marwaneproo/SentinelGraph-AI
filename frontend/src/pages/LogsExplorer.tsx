import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  ShieldCheck, 
  ShieldAlert, 
  Eye, 
  RefreshCw, 
  Play, 
  ChevronLeft, 
  ChevronRight, 
  Terminal,
  FileCheck2,
  AlertTriangle
} from 'lucide-react';
import { SecurityLog, LogListResponse } from '../types';
import { request } from '../services/api';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';

export const LogsExplorer: React.FC = () => {
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [serverId, setServerId] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Inspector & Verification modals
  const [selectedLog, setSelectedLog] = useState<SecurityLog | null>(null);
  const [verificationResult, setVerificationResult] = useState<{
    logId: string;
    valid: boolean;
    hash: string;
    message: string;
  } | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', page.toString());
      params.set('page_size', pageSize.toString());
      if (search) params.set('search', search);
      if (severity) params.set('severity', severity);
      if (eventType) params.set('event_type', eventType);
      if (serverId) params.set('server_id', serverId);

      const res = await request<LogListResponse>(`/logs?${params.toString()}`);
      setLogs(res.logs);
      setTotal(res.total);
    } catch (e) {
      console.error('Failed to load logs:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, severity, eventType, serverId]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchLogs();
  };

  const handleVerifyLog = async (logId: string) => {
    setIsVerifying(true);
    try {
      const res = await request<any>(`/logs/${logId}/verify`);
      setVerificationResult({
        logId,
        valid: res.integrity_valid,
        hash: res.calculated_hash,
        message: res.message
      });
    } catch (e: any) {
      setVerificationResult({
        logId,
        valid: false,
        hash: '',
        message: e.message || 'Verification failed.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Search and Filters Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
        <form onSubmit={handleSearchSubmit} className="flex flex-wrap gap-3">
          <div className="flex-1 min-w-[260px] relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search message, IP, username, or event type..."
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
            <option value="INFO">Info</option>
          </select>

          <select
            value={eventType}
            onChange={(e) => {
              setEventType(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition"
          >
            <option value="">All Event Types</option>
            <option value="AUTH_FAILED">AUTH_FAILED</option>
            <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
            <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
            <option value="PORT_SCAN">PORT_SCAN</option>
            <option value="SSH_LOGIN">SSH_LOGIN</option>
          </select>

          <select
            value={serverId}
            onChange={(e) => {
              setServerId(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition"
          >
            <option value="">All Servers</option>
            <option value="SRV-PROD-AUTH-01">SRV-PROD-AUTH-01</option>
            <option value="SRV-PROD-APP-02">SRV-PROD-APP-02</option>
            <option value="SRV-FINANCE-DB-03">SRV-FINANCE-DB-03</option>
            <option value="SRV-EDGE-GATEWAY-04">SRV-EDGE-GATEWAY-04</option>
            <option value="SRV-PAYMENTS-05">SRV-PAYMENTS-05</option>
          </select>

          <button
            type="submit"
            className="px-4 py-2.5 rounded-xl font-semibold text-xs bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-950 transition"
          >
            Search Logs
          </button>
        </form>

        <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/80">
          <span>Found <strong className="text-white font-mono">{total}</strong> security logs in MongoDB collection</span>
          <div className="flex items-center gap-1.5 text-cyan-400 font-mono text-[11px]">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>SHA-256 Audit Chain Active</span>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 font-semibold uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">User</th>
                <th className="py-3 px-4">Server</th>
                <th className="py-3 px-4">Message</th>
                <th className="py-3 px-4 text-center">Integrity</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500 font-sans">
                    <div className="w-6 h-6 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin mx-auto mb-2" />
                    Querying logs...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500 font-sans">
                    No matching logs found.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log._id || log.integrity_hash} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                      {log.timestamp ? log.timestamp.replace('T', ' ').slice(0, 19) : ''}
                    </td>
                    <td className="py-3 px-4">
                      <Badge variant={log.severity} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-cyan-300 font-semibold">{log.event_type}</td>
                    <td className="py-3 px-4 text-rose-300">{log.source_ip}</td>
                    <td className="py-3 px-4 text-amber-300">{log.username || '-'}</td>
                    <td className="py-3 px-4 text-purple-300 whitespace-nowrap">{log.server_id}</td>
                    <td className="py-3 px-4 text-slate-300 font-sans max-w-xs truncate" title={log.message}>
                      {log.message}
                    </td>
                    <td className="py-3 px-4 text-center">
                      <button
                        onClick={() => handleVerifyLog(log._id || log.integrity_hash)}
                        className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                        title={`Verify SHA-256 seal (${log.integrity_hash.slice(0, 8)}...)`}
                      >
                        <ShieldCheck className="w-3 h-3 text-cyan-400" />
                        <span>SHA-256</span>
                      </button>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
                        title="Inspect full log details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination controls */}
        <div className="px-6 py-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing Page <span className="font-bold text-white">{page}</span> of <span className="font-bold text-white">{totalPages}</span>
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
      </div>

      {/* Log Details Inspector Modal */}
      {selectedLog && (
        <Modal
          isOpen={!!selectedLog}
          onClose={() => setSelectedLog(null)}
          title={`Log Forensic Record [${selectedLog.event_type}]`}
          maxWidth="3xl"
        >
          <div className="space-y-4 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
              <div>
                <span className="text-slate-500">Timestamp:</span>
                <p className="text-white mt-0.5">{selectedLog.timestamp}</p>
              </div>
              <div>
                <span className="text-slate-500">Server:</span>
                <p className="text-cyan-400 mt-0.5">{selectedLog.server_name} ({selectedLog.server_id})</p>
              </div>
              <div>
                <span className="text-slate-500">Source IP:</span>
                <p className="text-rose-400 mt-0.5">{selectedLog.source_ip}</p>
              </div>
              <div>
                <span className="text-slate-500">Target User:</span>
                <p className="text-amber-400 mt-0.5">{selectedLog.username || 'N/A'}</p>
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-semibold font-sans">Full Message:</span>
              <p className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-200 mt-1 font-sans">
                {selectedLog.message}
              </p>
            </div>

            <div>
              <span className="text-slate-400 font-semibold font-sans">SHA-256 Cryptographic Hash Seal:</span>
              <p className="p-2.5 bg-slate-950 rounded-lg border border-cyan-500/30 text-cyan-300 break-all mt-1">
                {selectedLog.integrity_hash}
              </p>
            </div>

            {selectedLog.prev_hash && (
              <div>
                <span className="text-slate-400 font-semibold font-sans">Blockchain Previous Hash Chaining:</span>
                <p className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-slate-400 break-all mt-1">
                  {selectedLog.prev_hash}
                </p>
              </div>
            )}

            {selectedLog.details && (
              <div>
                <span className="text-slate-400 font-semibold font-sans">Structured Telemetry Details:</span>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 overflow-x-auto mt-1">
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </Modal>
      )}

      {/* SHA-256 Verification Result Modal */}
      {verificationResult && (
        <Modal
          isOpen={!!verificationResult}
          onClose={() => setVerificationResult(null)}
          title="Cryptographic Log Integrity Verification"
          maxWidth="lg"
        >
          <div className="space-y-4 text-center py-2">
            <div className="w-12 h-12 rounded-2xl mx-auto flex items-center justify-center bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              {verificationResult.valid ? (
                <FileCheck2 className="w-6 h-6 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-6 h-6 text-rose-500" />
              )}
            </div>

            <div>
              <h4 className="text-base font-bold text-white">
                {verificationResult.valid ? 'Integrity Verified: Valid Seal' : 'Forensic Warning: Integrity Compromised!'}
              </h4>
              <p className="text-xs text-slate-400 mt-1">{verificationResult.message}</p>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-left space-y-1">
              <span className="text-[10px] uppercase font-mono text-slate-500">Calculated Hash Seal:</span>
              <p className="text-xs font-mono text-cyan-300 break-all">{verificationResult.hash}</p>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
