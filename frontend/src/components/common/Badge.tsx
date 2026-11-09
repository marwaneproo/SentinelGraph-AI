import React from 'react';

interface BadgeProps {
  variant: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE' | 'ACTIVE' | 'OFFLINE';
  label?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({ variant, label, size = 'md' }) => {
  const displayLabel = label || variant;

  const getStyle = () => {
    switch (variant) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/30 animate-pulse';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'INFO':
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
      case 'NEW':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'INVESTIGATING':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'RESOLVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'FALSE_POSITIVE':
        return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30';
      case 'ACTIVE':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'OFFLINE':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

  const sizeStyle = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center font-medium rounded-full border ${getStyle()} ${sizeStyle}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {displayLabel}
    </span>
  );
};
