import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function RiskBadge({ verdict, riskLevel, size = 'md' }) {
  const v = (verdict || '').toUpperCase();
  const r = (riskLevel || '').toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let Icon = AlertTriangle;

  if (v === 'PHISHING' || r === 'CRITICAL' || r === 'HIGH') {
    colorClasses = 'bg-red-500/15 text-red-400 border-red-500/30';
    Icon = ShieldAlert;
  } else if (v === 'SUSPICIOUS' || r === 'MEDIUM') {
    colorClasses = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    Icon = AlertTriangle;
  } else if (v === 'LEGITIMATE' || r === 'LOW') {
    colorClasses = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    Icon = ShieldCheck;
  }

  const sizeClasses = size === 'lg' 
    ? 'px-3.5 py-1.5 text-sm gap-2 font-semibold' 
    : size === 'sm' 
    ? 'px-2 py-0.5 text-xs gap-1 font-medium' 
    : 'px-2.5 py-1 text-xs gap-1.5 font-medium';

  return (
    <span className={`inline-flex items-center rounded-full border ${colorClasses} ${sizeClasses}`}>
      <Icon className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />
      <span>{verdict || riskLevel || 'UNKNOWN'}</span>
    </span>
  );
}
