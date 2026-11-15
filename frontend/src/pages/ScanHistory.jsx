import React, { useState, useEffect } from 'react';
import { History, Filter, Eye, X, Clock, Layers } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import api from '../services/api';

export default function ScanHistory() {
  const [records, setRecords] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  useEffect(() => {
    fetchHistory();
  }, [page, typeFilter, verdictFilter]);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getScanHistory(page, 15, typeFilter, verdictFilter);
      setRecords(data.records || []);
      setTotalRecords(data.total_records || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err) {
      console.error('Failed to query history:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleInspect = async (id) => {
    setLoadingDetail(true);
    try {
      const detail = await api.getScanDetail(id);
      setSelectedScan(detail);
    } catch (err) {
      console.error('Failed to load scan detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <History className="h-6 w-6 text-cyan-400" />
          Scan Audit History Log
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Persistent audit record of all past URL and Email scans with full feature snapshots.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-sm">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
          <Filter className="h-4 w-4 text-cyan-400" />
          Filter Scans:
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          {/* Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="">All Scan Types</option>
            <option value="URL">URLs Only</option>
            <option value="EMAIL">Emails Only</option>
          </select>

          {/* Verdict Filter */}
          <select
            value={verdictFilter}
            onChange={(e) => { setVerdictFilter(e.target.value); setPage(1); }}
            className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="">All Verdicts</option>
            <option value="PHISHING">Phishing Only</option>
            <option value="SUSPICIOUS">Suspicious Only</option>
            <option value="LEGITIMATE">Legitimate Only</option>
          </select>
        </div>
      </div>

      {/* Records Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-6 py-3.5 font-semibold">Type</th>
                <th className="px-6 py-3.5 font-semibold">Target / Content Summary</th>
                <th className="px-6 py-3.5 font-semibold">Verdict</th>
                <th className="px-6 py-3.5 font-semibold">Probability</th>
                <th className="px-6 py-3.5 font-semibold">Latency</th>
                <th className="px-6 py-3.5 font-semibold">Date & Time</th>
                <th className="px-6 py-3.5 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-500">
                    Loading records from database...
                  </td>
                </tr>
              ) : records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-500">
                    No scan records matching current filter criteria.
                  </td>
                </tr>
              ) : (
                records.map((rec) => (
                  <tr key={rec.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-6 py-3.5 font-mono font-bold text-cyan-400">{rec.scan_type}</td>
                    <td className="px-6 py-3.5 font-mono max-w-sm truncate" title={rec.input_summary}>
                      {rec.input_summary}
                    </td>
                    <td className="px-6 py-3.5">
                      <RiskBadge verdict={rec.verdict} riskLevel={rec.risk_level} size="sm" />
                    </td>
                    <td className="px-6 py-3.5 font-mono">{(rec.confidence_score * 100).toFixed(1)}%</td>
                    <td className="px-6 py-3.5 font-mono text-slate-400">{rec.execution_time_ms} ms</td>
                    <td className="px-6 py-3.5 text-slate-400 font-mono">
                      {new Date(rec.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3.5 text-right">
                      <button
                        onClick={() => handleInspect(rec.id)}
                        className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:border-cyan-500 hover:text-cyan-400 transition-colors inline-flex items-center gap-1"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="flex items-center justify-between border-t border-slate-800 px-6 py-3 text-xs text-slate-400">
          <span>
            Showing page <strong className="text-white">{page}</strong> of <strong className="text-white">{totalPages}</strong> ({totalRecords} records)
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page <= 1}
              className="rounded border border-slate-800 bg-slate-950 px-3 py-1 hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page >= totalPages}
              className="rounded border border-slate-800 bg-slate-950 px-3 py-1 hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Inspect Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="relative max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <RiskBadge verdict={selectedScan.verdict} riskLevel={selectedScan.risk_level} size="md" />
                <span className="text-sm font-mono font-bold text-white">{selectedScan.scan_type} Details</span>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <p className="text-[10px] uppercase font-semibold text-slate-500">Input Summary</p>
                <p className="mt-1 font-mono text-slate-200 bg-slate-950 p-2.5 rounded-lg border border-slate-800 break-all">
                  {selectedScan.input_summary}
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <span className="text-slate-500 text-[10px] uppercase font-semibold">Confidence Score</span>
                  <p className="font-mono text-lg font-bold text-white mt-1">{(selectedScan.confidence_score * 100).toFixed(1)}%</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <span className="text-slate-500 text-[10px] uppercase font-semibold">Inference Latency</span>
                  <p className="font-mono text-lg font-bold text-white mt-1">{selectedScan.execution_time_ms} ms</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <span className="text-slate-500 text-[10px] uppercase font-semibold">Scan UUID</span>
                  <p className="font-mono text-[10px] text-cyan-400 mt-1 truncate" title={selectedScan.id}>{selectedScan.id}</p>
                </div>
              </div>

              {/* Explanations */}
              {selectedScan.explanation?.human_readable_reasons && (
                <div>
                  <p className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Human Readable Reasons</p>
                  <ul className="list-disc list-inside space-y-1 bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300">
                    {selectedScan.explanation.human_readable_reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Feature snapshot table if present */}
              {selectedScan.features && Object.keys(selectedScan.features).length > 0 && (
                <div>
                  <p className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Feature Snapshot</p>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 max-h-48 overflow-y-auto">
                    {Object.entries(selectedScan.features).map(([k, v]) => (
                      <div key={k} className="text-[11px]">
                        <span className="text-slate-500">{k}:</span> <span className="font-mono text-slate-300 font-semibold">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
