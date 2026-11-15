import React, { useState } from 'react';
import { 
  Mail, 
  Send, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Flame, 
  Link as LinkIcon, 
  UserCheck, 
  Cpu, 
  Clock 
} from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import api from '../services/api';

const SAMPLE_EMAIL_PRESETS = [
  {
    name: 'Urgent Account Suspension Phish',
    sender: 'security-alert@micros0ft-live-protection.com',
    subject: 'URGENT: Your Office 365 Account is Suspended - Action Required',
    body: 'Dear user, unusual login attempts from Moscow, Russia were detected on your Office 365 account. Your account has been temporarily locked to prevent data loss. You must verify your credentials immediately at http://192.168.1.100/secure-login or your email inbox will be permanently deleted within 24 hours.'
  },
  {
    name: 'Executive Wire Fraud Scam',
    sender: 'executive-wire@ceo-office-urgent.work',
    subject: 'CONFIDENTIAL: Urgent Wire Transfer Required before 3 PM',
    body: 'Are you at your desk? I am currently in a closed-door acquisition meeting and need you to urgently process an international wire transfer of $48,500 to our vendor escrow account. Keep this strictly confidential. Reply to this email immediately with confirmation.'
  },
  {
    name: 'Legitimate Engineering Roadmap Sync',
    sender: 'sarah.jenkins@acmecorp.com',
    subject: 'Q3 Engineering Roadmap Review - Tuesday 10 AM',
    body: 'Hi team, please review the attached slides before our roadmap synchronization meeting tomorrow morning. We will prioritize the microservices migration and API latency improvements. Let me know if you have agenda items to add.'
  }
];

export default function EmailScanner() {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (sample = null) => {
    const s = sample ? sample.sender : sender;
    const sub = sample ? sample.subject : subject;
    const b = sample ? sample.body : body;

    if (!sub.trim() && !b.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.scanEmail({ sender: s, subject: sub, body: b });
      setResult(data);
    } catch (err) {
      setError(err.message || 'Error occurred during email NLP classification.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset) => {
    setSender(preset.sender);
    setSubject(preset.subject);
    setBody(preset.body);
    handleScan(preset);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Mail className="h-6 w-6 text-cyan-400" />
          Phishing Email NLP Detection Engine
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Evaluates linguistic urgency, social engineering indicators, header discrepancies, and embedded link destinations.
        </p>
      </div>

      {/* Input Form Card */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-sm shadow-sm space-y-4">
        {/* Presets */}
        <div className="flex flex-wrap items-center gap-2 pb-2 border-b border-slate-800">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Presets:</span>
          {SAMPLE_EMAIL_PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => loadPreset(p)}
              className="rounded-lg border border-slate-800 bg-slate-950/60 px-2.5 py-1 text-xs text-slate-300 hover:border-cyan-500/40 hover:text-cyan-400 transition-colors"
            >
              {p.name}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Sender Address (Header)
            </label>
            <input
              type="text"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="e.g., security-alert@micros0ft-live-protection.com"
              className="w-full rounded-xl border border-slate-800 bg-slate-950 px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Subject Line
            </label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="e.g., URGENT: Your account is suspended..."
              className="w-full rounded-xl border border-slate-800 bg-slate-950 px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            Email Body Content
          </label>
          <textarea
            rows={5}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Paste raw email text or MIME content with headers and links..."
            className="w-full rounded-xl border border-slate-800 bg-slate-950 p-3.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono leading-relaxed"
          />
        </div>

        <div className="flex justify-end">
          <button
            onClick={() => handleScan()}
            disabled={loading || (!subject.trim() && !body.trim())}
            className="flex items-center gap-2 rounded-xl bg-cyan-500 px-6 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-sm shadow-cyan-500/20"
          >
            {loading ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                <span>Running NLP Pipeline...</span>
              </>
            ) : (
              <>
                <Send className="h-4 w-4" />
                <span>Scan Email Content</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-4 text-red-400 text-sm flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 shrink-0 text-red-400 mt-0.5" />
          <div>
            <span className="font-semibold">Email Analysis Error:</span>
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
                <h2 className="mt-3 text-lg font-bold text-white font-mono">{result.subject || '(No Subject)'}</h2>
                {result.sender && (
                  <p className="mt-0.5 text-xs text-slate-400 font-mono">From: {result.sender}</p>
                )}
              </div>

              {/* Confidence Score Gauge */}
              <div className="flex flex-col items-end">
                <span className="text-xs text-slate-400 uppercase font-semibold">Phishing Probability</span>
                <span className={`text-3xl font-mono font-extrabold ${
                  result.confidence_score >= 0.70 ? 'text-red-400' : result.confidence_score >= 0.40 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {(result.confidence_score * 100).toFixed(1)}%
                </span>
                <span className="text-[11px] text-slate-500">NLP TF-IDF & Heuristics</span>
              </div>
            </div>

            {/* Linguistic Urgency Meter */}
            <div className="mt-5 pt-4 border-t border-slate-800/80">
              <div className="flex justify-between text-xs mb-1.5 font-medium">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <Flame className="h-4 w-4 text-amber-400" />
                  Urgency & Pressure Cues Score:
                </span>
                <span className="font-mono text-cyan-400">
                  {(result.indicators?.urgency_score * 100).toFixed(0)}%
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    result.indicators?.urgency_score > 0.6 ? 'bg-red-500' : result.indicators?.urgency_score > 0.3 ? 'bg-amber-400' : 'bg-emerald-400'
                  }`}
                  style={{ width: `${(result.indicators?.urgency_score || 0) * 100}%` }}
                />
              </div>
            </div>
          </div>

          {/* Social Engineering & Indicators Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Social Engineering Categories */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                Detected Social Engineering Patterns
              </h3>
              {result.indicators?.social_engineering?.categories?.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {result.indicators.social_engineering.categories.map((cat, idx) => (
                    <span key={idx} className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-1 text-xs text-red-300 font-medium">
                      {cat}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500">No overt social engineering coercion signatures matched.</p>
              )}

              {/* Matched phrases */}
              {result.indicators?.social_engineering?.matched_phrases?.length > 0 && (
                <div className="mt-2 pt-2 border-t border-slate-800">
                  <p className="text-[11px] text-slate-400 font-semibold mb-1">Key Coercion Phrases:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {result.indicators.social_engineering.matched_phrases.map((phrase, idx) => (
                      <span key={idx} className="font-mono text-[11px] bg-slate-950 border border-slate-800 px-2 py-0.5 rounded text-amber-300">
                        "{phrase}"
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Sender Domain Analysis */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <UserCheck className="h-4 w-4 text-cyan-400" />
                Sender Header Analysis
              </h3>
              {result.indicators?.sender_analysis?.anomalies?.length > 0 ? (
                <ul className="list-disc list-inside space-y-1 text-xs text-amber-300">
                  {result.indicators.sender_analysis.anomalies.map((anom, idx) => (
                    <li key={idx}>{anom}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4" />
                  Sender domain syntax passed standard sanity checks.
                </p>
              )}
            </div>
          </div>

          {/* Embedded Links Inspection */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <LinkIcon className="h-4 w-4 text-cyan-400" />
              Embedded Hyperlink Inspection ({result.indicators?.embedded_links?.length || 0} discovered)
            </h3>
            {result.indicators?.embedded_links?.length > 0 ? (
              <div className="divide-y divide-slate-800 border border-slate-800 rounded-lg overflow-hidden">
                {result.indicators.embedded_links.map((linkItem, idx) => (
                  <div key={idx} className="p-3 bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="font-mono text-xs text-slate-200 break-all">{linkItem.url}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      {linkItem.is_suspicious ? (
                        <span className="rounded bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 text-[11px] font-semibold">
                          SUSPICIOUS DESTINATION
                        </span>
                      ) : (
                        <span className="rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 text-[11px] font-semibold">
                          CLEAN
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">No embedded URLs discovered in message body.</p>
            )}
          </div>

          {/* Explanation Section */}
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-5 space-y-2">
            <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Automated Threat Synthesis</h4>
            <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
              {result.explanation?.human_readable_reasons?.map((reason, idx) => (
                <li key={idx}>{reason}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
