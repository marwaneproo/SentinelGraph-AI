import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color?: 'cyan' | 'red' | 'amber' | 'emerald' | 'purple';
  trend?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'cyan',
  trend,
}) => {
  const colorMap = {
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20 shadow-cyan-950/20',
    red: 'text-rose-400 bg-rose-500/10 border-rose-500/20 shadow-rose-950/20',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/20 shadow-amber-950/20',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20 shadow-emerald-950/20',
    purple: 'text-purple-400 bg-purple-500/10 border-purple-500/20 shadow-purple-950/20',
  };

  return (
    <div className="bg-[#0f172a]/90 backdrop-blur border border-slate-800/80 rounded-xl p-5 hover:border-slate-700 transition shadow-lg relative overflow-hidden group">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider font-semibold text-slate-400">{title}</p>
          <h3 className="text-3xl font-extrabold text-white mt-2 tracking-tight">{value}</h3>
          {subtitle && <p className="text-xs text-slate-400 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-xl border ${colorMap[color]} transition-transform group-hover:scale-110`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
      {trend && (
        <div className="mt-3 pt-3 border-t border-slate-800/60 flex items-center text-xs text-slate-400">
          <span className="text-emerald-400 font-medium mr-1.5">{trend}</span>
          <span>vs baseline</span>
        </div>
      )}
      <div className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent opacity-0 group-hover:opacity-100 transition" />
    </div>
  );
};
