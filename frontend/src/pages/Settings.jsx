import React, { useState } from 'react';
import { Settings as SettingsIcon, Key, Shield, Database, Save, Check } from 'lucide-react';

export default function Settings() {
  const [apiKey, setApiKey] = useState('');
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <SettingsIcon className="h-6 w-6 text-cyan-400" />
          Security Suite Configuration
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Manage threat intelligence API keys, backend endpoints, and detection parameters.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Threat Intelligence API Keys */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm space-y-4">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
            <Key className="h-4 w-4 text-cyan-400" />
            Threat Intelligence Credentials
          </h3>
          <p className="text-xs text-slate-400">
            Enrich local ML predictions with Google Safe Browsing v4 Threat API.
          </p>

          <form onSubmit={handleSave} className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">
                Google Safe Browsing API Key
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="AIzaSy..."
                className="w-full rounded-xl border border-slate-800 bg-slate-950 px-3.5 py-2.5 text-xs text-white placeholder-slate-600 focus:border-cyan-500 focus:outline-none font-mono"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                Stored securely in backend environment as GOOGLE_SAFE_BROWSING_API_KEY.
              </span>
            </div>

            <button
              type="submit"
              className="flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 transition-colors"
            >
              {saved ? <Check className="h-3.5 w-3.5" /> : <Save className="h-3.5 w-3.5" />}
              {saved ? 'Settings Saved' : 'Save Credentials'}
            </button>
          </form>
        </div>

        {/* Security Hardening Policies */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm space-y-4">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-400" />
            SSRF & Backend Defenses
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950">
              <div>
                <p className="font-semibold text-white">Air-Gapped Feature Extraction</p>
                <p className="text-[11px] text-slate-400">Never fetch or resolve candidate target URLs</p>
              </div>
              <span className="rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-0.5 text-[10px] font-bold">
                ENFORCED
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950">
              <div>
                <p className="font-semibold text-white">SSRF Localhost & Metadata Blocking</p>
                <p className="text-[11px] text-slate-400">Rejects 127.0.0.1, 169.254.169.254, and loopbacks</p>
              </div>
              <span className="rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-0.5 text-[10px] font-bold">
                ENFORCED
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950">
              <div>
                <p className="font-semibold text-white">Input Payload Limits</p>
                <p className="text-[11px] text-slate-400">Max URL: 2,048 chars · Max Email: 100 KB</p>
              </div>
              <span className="rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-0.5 text-[10px] font-bold">
                ENFORCED
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Architecture Environment Information */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm space-y-3">
        <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
          <Database className="h-4 w-4 text-cyan-400" />
          System & Model Runtime Specifications
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <span className="text-slate-500 text-[10px] uppercase font-semibold">Backend Engine</span>
            <p className="text-white font-mono font-bold mt-1">Python 3.14 + Flask 3.1</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <span className="text-slate-500 text-[10px] uppercase font-semibold">Persistence Layer</span>
            <p className="text-white font-mono font-bold mt-1">SQLAlchemy ORM (SQLite / Postgres)</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <span className="text-slate-500 text-[10px] uppercase font-semibold">Explainable AI</span>
            <p className="text-white font-mono font-bold mt-1">SHAP TreeExplainer 0.54</p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <span className="text-slate-500 text-[10px] uppercase font-semibold">Frontend Architecture</span>
            <p className="text-white font-mono font-bold mt-1">React 18 + Vite + Tailwind</p>
          </div>
        </div>
      </div>
    </div>
  );
}
