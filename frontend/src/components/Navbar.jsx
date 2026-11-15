import React from 'react';
import { Shield, Activity, Moon, Sun, Terminal } from 'lucide-react';

export default function Navbar({ isOnline, darkMode, setDarkMode }) {
  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 backdrop-blur-md">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-md shadow-cyan-500/20">
          <Shield className="h-5 w-5 text-slate-950" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold tracking-tight text-white text-lg">PhishShield</span>
            <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-bold text-cyan-400 border border-cyan-500/30">AI DEFENSE</span>
          </div>
          <p className="text-[11px] text-slate-400">Intelligent Threat Detection Engine</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Backend health status badge */}
        <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900/80 px-3 py-1 text-xs">
          <span className={`h-2 w-2 rounded-full ${isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></span>
          <span className="text-slate-300 font-mono text-[11px]">{isOnline ? 'ENGINE ONLINE' : 'DISCONNECTED'}</span>
        </div>

        {/* Dark/Light mode toggle */}
        <button
          onClick={() => setDarkMode(!darkMode)}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:border-slate-700 hover:text-white transition-colors"
          title="Toggle Theme"
        >
          {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>
    </header>
  );
}
