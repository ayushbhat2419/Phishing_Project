import React, { useState } from 'react';
import { 
  Globe, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Layers, 
  Info, 
  ExternalLink,
  Cpu,
  Clock
} from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import api from '../services/api';

const SAMPLE_PRESETS = [
  { label: 'PayPal Impersonation Phish', url: 'http://paypal-security-alert.account-verification-service.xyz/login.php' },
  { label: 'Direct IP Credential Harvester', url: 'http://192.168.1.100/secure/chase/login.html' },
  { label: 'Subdomain Chain Attack', url: 'http://wellsfargo.verify-online-access.com.customer-update.top/login' },
  { label: 'Benign Python Documentation', url: 'https://docs.python.org/3/library/urllib.parse.html' }
];

export default function UrlScanner() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (targetUrl = urlInput) => {
    if (!targetUrl.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.scanUrl(targetUrl.trim());
      setResult(data);
    } catch (err) {
      setError(err.message || 'Error occurred during URL inspection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Globe className="h-6 w-6 text-cyan-400" />
          Phishing URL Detection Engine
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Extracts 18 lexical and structural features and predicts maliciousness via trained ensemble models with SHAP explainability.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm shadow-sm space-y-4">
        <form 
          onSubmit={(e) => { e.preventDefault(); handleScan(); }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter suspicious or candidate URL (e.g., http://paypal-security-check.xyz/login)..."
              className="w-full rounded-xl border border-slate-800 bg-slate-950 pl-10 pr-4 py-3 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm shadow-cyan-500/20"
          >
            {loading ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                <span>Analyzing Vector...</span>
              </>
            ) : (
              <>
                <ShieldAlert className="h-4 w-4" />
                <span>Analyze URL</span>
              </>
            )}
          </button>
        </form>

        {/* Quick-test Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Presets:</span>
          {SAMPLE_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => {
                setUrlInput(preset.url);
                handleScan(preset.url);
              }}
              className="rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-1 text-xs text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400 transition-colors"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-4 text-red-400 text-sm flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 shrink-0 text-red-400 mt-0.5" />
          <div>
            <span className="font-semibold">Security Alert or Validation Error:</span>
            <p className="mt-0.5 text-xs text-red-300">{error}</p>
          </div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Main Verdict Card */}
          <div className={`rounded-2xl border p-6 backdrop-blur-sm transition-all ${
            result.verdict === 'PHISHING'
              ? 'border-red-500/30 bg-red-950/10 cyber-glow-danger'
              : result.verdict === 'SUSPICIOUS'
              ? 'border-amber-500/30 bg-amber-950/10'
              : 'border-emerald-500/30 bg-emerald-950/10 cyber-glow-success'
          }`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <RiskBadge verdict={result.verdict} riskLevel={result.risk_level} size="lg" />
                  <span className="text-xs text-slate-400 font-mono flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" /> {result.execution_time_ms} ms inference
                  </span>
                </div>
                <h2 className="mt-3 text-lg font-mono font-bold text-white break-all">{result.target}</h2>
              </div>

              {/* Confidence Score Gauge */}
              <div className="flex flex-col items-end">
                <span className="text-xs text-slate-400 uppercase font-semibold">Phishing Probability</span>
                <span className={`text-3xl font-mono font-extrabold ${
                  result.confidence_score >= 0.70 ? 'text-red-400' : result.confidence_score >= 0.40 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {(result.confidence_score * 100).toFixed(1)}%
                </span>
                <span className="text-[11px] text-slate-500">Ensemble Tree Confidence</span>
              </div>
            </div>

            {/* Threat Intelligence Feed Status */}
            {result.threat_intelligence && (
              <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-400">Threat Intel Provider:</span>
                  <span className="text-cyan-400 font-mono">{result.threat_intelligence.provider}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-400">Status:</span>
                  <span className={`font-mono px-2 py-0.5 rounded text-[11px] ${
                    result.threat_intelligence.matched ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'bg-slate-800 text-slate-300'
                  }`}>
                    {result.threat_intelligence.status}
                  </span>
                </div>
                <div className="text-slate-400 text-[11px]">
                  {result.threat_intelligence.threat_details}
                </div>
              </div>
            )}
          </div>

          {/* Explainable AI (SHAP) Section */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm space-y-4">
            <div className="flex items-center gap-2 text-white font-semibold">
              <Cpu className="h-5 w-5 text-cyan-400" />
              <h3>Explainable AI (SHAP Feature Attributions)</h3>
            </div>
            <p className="text-xs text-slate-400">
              Shapley additive explanations reveal which structural features pushed the model toward this classification:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {result.explanation?.top_contributing_features?.map((factor, idx) => (
                <div key={idx} className="rounded-lg border border-slate-800/80 bg-slate-950/50 p-4 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{factor.title}</span>
                    <span className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded ${
                      factor.shap_value > 0 
                        ? 'bg-red-500/15 text-red-400 border border-red-500/30' 
                        : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      SHAP: {factor.shap_value > 0 ? `+${factor.shap_value.toFixed(4)}` : factor.shap_value?.toFixed(4)}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{factor.description}</p>
                </div>
              ))}
            </div>

            {/* Human Readable Summary */}
            <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/10 p-4">
              <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2">Automated Security Insights</h4>
              <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
                {result.explanation?.human_readable_reasons?.map((reason, idx) => (
                  <li key={idx}>{reason}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Extracted 18-Feature Snapshot Grid */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm space-y-4">
            <div className="flex items-center gap-2 text-white font-semibold">
              <Layers className="h-5 w-5 text-cyan-400" />
              <h3>Extracted URL Feature Matrix (18 Attributes)</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 text-xs">
              {Object.entries(result.features || {}).map(([key, val]) => (
                <div key={key} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                  <p className="text-[10px] uppercase font-semibold text-slate-500 truncate" title={key}>{key.replace(/_/g, ' ')}</p>
                  <p className="mt-1 text-sm font-mono font-bold text-slate-200">
                    {typeof val === 'boolean' ? (val ? 'TRUE' : 'FALSE') : String(val)}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
