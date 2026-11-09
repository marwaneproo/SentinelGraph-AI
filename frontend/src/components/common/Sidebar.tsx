import React from 'react';
import { 
  LayoutDashboard, 
  Terminal, 
  ShieldAlert, 
  Network, 
  Bot, 
  Server, 
  Sliders, 
  LogOut, 
  Shield, 
  Radio
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export type NavTab = 
  | 'dashboard' 
  | 'logs' 
  | 'alerts' 
  | 'graph' 
  | 'ai' 
  | 'servers' 
  | 'rules';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const { user, logout, role } = useAuth();

  const navItems = [
    { id: 'dashboard' as NavTab, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'logs' as NavTab, label: 'Logs Explorer', icon: Terminal },
    { id: 'alerts' as NavTab, label: 'Alerts Management', icon: ShieldAlert },
    { id: 'graph' as NavTab, label: 'Threat Graph', icon: Network },
    { id: 'ai' as NavTab, label: 'AI Security Assistant', icon: Bot },
    { id: 'servers' as NavTab, label: 'Server Assets', icon: Server },
    { id: 'rules' as NavTab, label: 'Detection Rules', icon: Sliders },
  ];

  return (
    <aside className="w-64 bg-[#090d16] border-r border-slate-800 flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none">
      <div>
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-slate-800/80 gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-900/30">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="font-extrabold tracking-wider text-sm text-white flex items-center gap-1.5">
              <span>SentinelGraph</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                AI
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-medium">Intelligent Mini SIEM</p>
          </div>
        </div>

        {/* Live Status indicator */}
        <div className="px-6 py-3 border-b border-slate-800/50 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-slate-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-[11px] font-mono">SOC SENSORS ONLINE</span>
          </div>
          <span className="text-[10px] font-mono bg-slate-800 px-1.5 py-0.5 rounded text-cyan-400">4IIR NoSQL</span>
        </div>

        {/* Navigation Links */}
        <nav className="p-4 space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl font-medium text-xs transition duration-150 ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/10 text-cyan-300 border border-cyan-500/30 shadow-md shadow-cyan-950/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
                {isActive && (
                  <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400" />
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* User Card & Logout */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/60">
        <div className="flex items-center gap-3 p-2 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 flex items-center justify-center font-bold text-xs uppercase">
            {user?.username.slice(0, 2) || 'US'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-slate-200 truncate">{user?.full_name || user?.username}</p>
            <p className="text-[10px] text-cyan-400 font-mono tracking-tight">{role}</p>
          </div>
          <button
            onClick={logout}
            title="Sign out"
            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
};
