import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'cyan' }) {
  const colorMap = {
    cyan: 'border-cyan-500/20 bg-cyan-950/20 text-cyan-400 group-hover:border-cyan-500/40',
    red: 'border-red-500/20 bg-red-950/20 text-red-400 group-hover:border-red-500/40',
    amber: 'border-amber-500/20 bg-amber-950/20 text-amber-400 group-hover:border-amber-500/40',
    emerald: 'border-emerald-500/20 bg-emerald-950/20 text-emerald-400 group-hover:border-emerald-500/40',
    purple: 'border-purple-500/20 bg-purple-950/20 text-purple-400 group-hover:border-purple-500/40',
  };

  const activeColor = colorMap[color] || colorMap.cyan;

  return (
    <div className="group relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm transition-all duration-200 hover:border-slate-700 hover:bg-slate-900/90 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</p>
          <h3 className="mt-2 text-2xl font-bold tracking-tight text-white">{value}</h3>
          {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
        </div>
        {Icon && (
          <div className={`rounded-xl border p-3 ${activeColor}`}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>
    </div>
  );
}
