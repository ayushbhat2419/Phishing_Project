import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Globe, Mail, Radio } from 'lucide-react';
import StatCard from '../components/StatCard';
import RiskBadge from '../components/RiskBadge';
import api from '../services/api';

export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  const summary = stats?.summary || {
    total_scans: 0,
    url_scans: 0,
    email_scans: 0,
    phishing_detected: 0,
    suspicious_detected: 0,
    legitimate_detected: 0,
    threat_intel_matches: 0
  };

  const risk = stats?.risk_distribution || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  const recent = stats?.recent_scans || [];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 p-6 shadow-sm">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            Security Telemetry & Operations
            <span className="flex h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping" />
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Real-time multi-model AI threat inference and threat feed intelligence.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('url-scanner')}
            className="flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 transition-colors shadow-sm shadow-cyan-500/20"
          >
            <Globe className="h-4 w-4" />
            Scan URL
          </button>
          <button
            onClick={() => onNavigate('email-scanner')}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/80 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 transition-colors"
          >
            <Mail className="h-4 w-4" />
            Scan Email
          </button>
        </div>
      </div>

      {/* Telemetry Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Scans Processed"
          value={summary.total_scans}
          subtitle={`${summary.url_scans} URLs · ${summary.email_scans} Emails`}
          icon={Radio}
          color="cyan"
        />
        <StatCard
          title="Phishing Detected"
          value={summary.phishing_detected}
          subtitle="Critical threats intercepted"
          icon={ShieldAlert}
          color="red"
        />
        <StatCard
          title="Suspicious Anomalies"
          value={summary.suspicious_detected}
          subtitle="Flagged for manual review"
          icon={AlertTriangle}
          color="amber"
        />
        <StatCard
          title="Legitimate Clean"
          value={summary.legitimate_detected}
          subtitle="Verified safe inputs"
          icon={ShieldCheck}
          color="emerald"
        />
      </div>

      {/* Risk Distribution & Intelligence Breakdown */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Risk Distribution Visual */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Risk Level Distribution</h3>
          <p className="text-xs text-slate-400 mt-1">Classification severity breakdown across all inputs</p>
          
          <div className="mt-6 space-y-4">
            <div>
              <div className="flex justify-between text-xs mb-1.5 font-medium">
                <span className="text-red-400 flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-red-400" /> Critical Severity</span>
                <span className="text-slate-300 font-mono">{risk.critical}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                <div 
                  className="h-full bg-red-500 rounded-full transition-all duration-500"
                  style={{ width: `${summary.total_scans ? (risk.critical / summary.total_scans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1.5 font-medium">
                <span className="text-amber-400 flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-400" /> High Severity</span>
                <span className="text-slate-300 font-mono">{risk.high}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                <div 
                  className="h-full bg-amber-500 rounded-full transition-all duration-500"
                  style={{ width: `${summary.total_scans ? (risk.high / summary.total_scans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1.5 font-medium">
                <span className="text-yellow-400 flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-yellow-400" /> Medium Severity</span>
                <span className="text-slate-300 font-mono">{risk.medium}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                <div 
                  className="h-full bg-yellow-500 rounded-full transition-all duration-500"
                  style={{ width: `${summary.total_scans ? (risk.medium / summary.total_scans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1.5 font-medium">
                <span className="text-emerald-400 flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-400" /> Low / Benign</span>
                <span className="text-slate-300 font-mono">{risk.low}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                <div 
                  className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                  style={{ width: `${summary.total_scans ? (risk.low / summary.total_scans) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Threat Intelligence Feed Stats */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm lg:col-span-2">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Active Threat Intelligence Feeds</h3>
          <p className="text-xs text-slate-400 mt-1">Cross-validation against authoritative threat registries</p>

          <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
              <p className="text-xs font-medium text-slate-400">OpenPhish Feed</p>
              <div className="mt-2 flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                <span className="text-sm font-bold text-white">Active (Cached)</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">Autonomous community feed</p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
              <p className="text-xs font-medium text-slate-400">PhishTank DB</p>
              <div className="mt-2 flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                <span className="text-sm font-bold text-white">Synchronized</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">Human-verified signatures</p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
              <p className="text-xs font-medium text-slate-400">Threat Intel Hits</p>
              <div className="mt-2 flex items-center gap-2">
                <span className="text-xl font-bold text-cyan-400">{summary.threat_intel_matches}</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">Known blacklist matches</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Recent Scan Activity</h3>
          <button
            onClick={() => onNavigate('history')}
            className="text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            View Full Audit Log →
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="px-6 py-3 font-semibold">Type</th>
                <th className="px-6 py-3 font-semibold">Target / Input</th>
                <th className="px-6 py-3 font-semibold">Verdict</th>
                <th className="px-6 py-3 font-semibold">Confidence</th>
                <th className="px-6 py-3 font-semibold">Latency</th>
                <th className="px-6 py-3 font-semibold">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {recent.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-500">
                    No scans logged yet. Run a URL or Email scan to generate activity telemetry.
                  </td>
                </tr>
              ) : (
                recent.map((rec) => (
                  <tr key={rec.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-6 py-3 font-mono font-bold text-cyan-400">{rec.scan_type}</td>
                    <td className="px-6 py-3 font-mono max-w-xs truncate" title={rec.input_summary}>
                      {rec.input_summary}
                    </td>
                    <td className="px-6 py-3">
                      <RiskBadge verdict={rec.verdict} riskLevel={rec.risk_level} size="sm" />
                    </td>
                    <td className="px-6 py-3 font-mono">{(rec.confidence_score * 100).toFixed(1)}%</td>
                    <td className="px-6 py-3 font-mono text-slate-400">{rec.execution_time_ms} ms</td>
                    <td className="px-6 py-3 text-slate-500">
                      {new Date(rec.created_at).toLocaleTimeString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
