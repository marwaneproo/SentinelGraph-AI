import React, { useState, useEffect } from 'react';
import { Server, Plus, Shield, Cpu, Activity, Trash2, CheckCircle2 } from 'lucide-react';
import { ServerAsset } from '../types';
import { request } from '../services/api';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { useAuth } from '../context/AuthContext';

export const ServersManagement: React.FC = () => {
  const { hasRole } = useAuth();
  const isAdmin = hasRole(['Administrator']);

  const [servers, setServers] = useState<ServerAsset[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // New server form
  const [newServer, setNewServer] = useState({
    server_id: '',
    hostname: '',
    ip_address: '',
    os_type: 'Linux',
    role: 'Application Server',
    criticality: 'HIGH',
    description: ''
  });

  const fetchServers = async () => {
    setIsLoading(true);
    try {
      const res = await request<ServerAsset[]>('/servers');
      setServers(res);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchServers();
  }, []);

  const handleCreateServer = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await request('/servers', {
        method: 'POST',
        body: JSON.stringify(newServer)
      });
      setIsModalOpen(false);
      setNewServer({
        server_id: '',
        hostname: '',
        ip_address: '',
        os_type: 'Linux',
        role: 'Application Server',
        criticality: 'HIGH',
        description: ''
      });
      await fetchServers();
    } catch (e: any) {
      alert(e.message || 'Error registering server');
    }
  };

  const handleDeleteServer = async (serverId: string) => {
    if (!confirm(`Are you sure you want to remove server ${serverId}?`)) return;
    try {
      await request(`/servers/${serverId}`, { method: 'DELETE' });
      await fetchServers();
    } catch (e: any) {
      alert(e.message || 'Error deleting server');
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <span>Monitored Enterprise Server Assets</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Registered endpoints transmitting authentication and system security logs.
          </p>
        </div>

        {isAdmin && (
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white shadow-lg transition flex items-center gap-1.5"
          >
            <Plus className="w-4 h-4" />
            <span>Register Server</span>
          </button>
        )}
      </div>

      {/* Grid of Servers */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {isLoading ? (
          <div className="col-span-full py-16 text-center text-xs text-slate-500">
            <div className="w-6 h-6 border-2 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin mx-auto mb-2" />
            Loading server infrastructure telemetry...
          </div>
        ) : servers.length === 0 ? (
          <div className="col-span-full py-16 text-center text-xs text-slate-500">
            No server assets registered.
          </div>
        ) : (
          servers.map((s) => (
            <div
              key={s.server_id}
              className="bg-[#0f172a] border border-slate-800/80 hover:border-slate-700 rounded-2xl p-5 shadow-lg transition space-y-4 relative group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                    <Cpu className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-white">{s.server_id}</h4>
                    <p className="text-[11px] text-slate-400 font-mono">{s.hostname}</p>
                  </div>
                </div>
                <Badge variant={s.criticality as any} size="sm" />
              </div>

              <div className="space-y-1.5 text-xs font-mono p-3 bg-slate-950/70 border border-slate-800/60 rounded-xl">
                <div className="flex justify-between">
                  <span className="text-slate-500">IP Address:</span>
                  <span className="text-cyan-400">{s.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Operating System:</span>
                  <span className="text-slate-300 font-sans">{s.os_type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Role:</span>
                  <span className="text-slate-300 font-sans">{s.role}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Ingested Logs:</span>
                  <span className="text-emerald-400 font-bold">{s.log_count ?? 0}</span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
                <div className="flex items-center gap-1.5 text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="font-mono text-[11px]">{s.status}</span>
                </div>

                {isAdmin && (
                  <button
                    onClick={() => handleDeleteServer(s.server_id)}
                    className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition"
                    title="Remove Server"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Register Server Modal */}
      {isModalOpen && (
        <Modal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          title="Register Monitored Server Asset"
          maxWidth="md"
        >
          <form onSubmit={handleCreateServer} className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-400 font-semibold mb-1">Server ID:</label>
              <input
                type="text"
                required
                placeholder="e.g. SRV-VAULT-06"
                value={newServer.server_id}
                onChange={(e) => setNewServer({ ...newServer, server_id: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Hostname:</label>
              <input
                type="text"
                required
                placeholder="e.g. vault-db.corp.internal"
                value={newServer.hostname}
                onChange={(e) => setNewServer({ ...newServer, hostname: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">IP Address:</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 10.0.3.99"
                  value={newServer.ip_address}
                  onChange={(e) => setNewServer({ ...newServer, ip_address: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Criticality:</label>
                <select
                  value={newServer.criticality}
                  onChange={(e) => setNewServer({ ...newServer, criticality: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-slate-400 font-semibold mb-1">Operating System & Role:</label>
              <div className="grid grid-cols-2 gap-3">
                <input
                  type="text"
                  placeholder="e.g. Ubuntu 24.04"
                  value={newServer.os_type}
                  onChange={(e) => setNewServer({ ...newServer, os_type: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
                <input
                  type="text"
                  placeholder="e.g. Vault Database"
                  value={newServer.role}
                  onChange={(e) => setNewServer({ ...newServer, role: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="px-3.5 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition"
              >
                Register
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
