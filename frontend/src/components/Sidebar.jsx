import React from 'react';
import { 
  LayoutDashboard, 
  Globe, 
  Mail, 
  History, 
  Gauge, 
  Settings as SettingsIcon,
  ShieldAlert
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'Security Overview', icon: LayoutDashboard },
    { id: 'url-scanner', label: 'URL Scanner', icon: Globe },
    { id: 'email-scanner', label: 'Email Scanner', icon: Mail },
    { id: 'history', label: 'Scan Audit Log', icon: History },
    { id: 'models', label: 'Model Benchmarks', icon: Gauge },
    { id: 'settings', label: 'Configuration', icon: SettingsIcon },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950/60 p-4 flex flex-col justify-between">
      <div className="space-y-1.5">
        <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
          Core Security Suite
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                  : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
              }`}
            >
              <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      {/* Security Threat Advisory Card */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-3.5">
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold">
          <ShieldAlert className="h-4 w-4" />
          <span>Active Threat Shield</span>
        </div>
        <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
          Heuristic & SHAP XAI models active with SSRF air-gapped protection.
        </p>
      </div>
    </aside>
  );
}
