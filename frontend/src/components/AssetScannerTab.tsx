import React, { useState, useRef, useMemo } from 'react';
import {
  UploadCloud,
  FileSpreadsheet,
  Download,
  Flame,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Search,
  Filter,
  Eye,
  FileText,
  Sparkles,
  Server,
  Building,
} from 'lucide-react';
import { AuditSummary, AssetAuditResult } from '../types';
import { threatApi } from '../services/api';
import { AssetDrawer } from './AssetDrawer';

export const AssetScannerTab: React.FC = () => {
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [auditSummary, setAuditSummary] = useState<AuditSummary | null>(null);
  const [auditFilename, setAuditFilename] = useState<string>('');
  const [selectedAsset, setSelectedAsset] = useState<AssetAuditResult | null>(null);
  const [tableFilter, setTableFilter] = useState<'all' | 'zero-day' | 'critical' | 'safe'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [uploadError, setUploadError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processFile(e.target.files[0]);
    }
  };

  const processFile = async (file: File) => {
    setLoading(true);
    setUploadError(null);
    try {
      const data = await threatApi.uploadAndAuditFile(file);
      setAuditSummary(data.summary);
      setAuditFilename(data.filename);
    } catch (err: any) {
      setUploadError(err.response?.data?.error || err.message || 'Failed to parse file.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadDemo = async () => {
    setLoading(true);
    setUploadError(null);
    try {
      const data = await threatApi.loadDemoAudit();
      setAuditSummary(data.summary);
      setAuditFilename(data.filename);
    } catch (err: any) {
      setUploadError(err.message || 'Failed to load demo audit.');
    } finally {
      setLoading(false);
    }
  };

  const filteredResults = useMemo(() => {
    if (!auditSummary) return [];
    return auditSummary.results.filter((item) => {
      // Status filter
      if (tableFilter === 'zero-day' && item.riskStatus !== 'ACTIVE ZERO-DAY') return false;
      if (tableFilter === 'critical' && item.riskStatus !== 'CRITICAL') return false;
      if (tableFilter === 'safe' && item.riskStatus !== 'SAFE') return false;

      // Search query
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase().trim();
      return (
        item.asset.softwareName.toLowerCase().includes(q) ||
        (item.asset.version && item.asset.version.toLowerCase().includes(q)) ||
        (item.asset.department && item.asset.department.toLowerCase().includes(q)) ||
        (item.asset.host && item.asset.host.toLowerCase().includes(q)) ||
        (item.asset.category && item.asset.category.toLowerCase().includes(q))
      );
    });
  }, [auditSummary, tableFilter, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Upload Zone & Actions Banner */}
      <div className="cyber-card p-6 bg-gradient-to-br from-[#0c121e]/95 via-[#0b0f19]/95 to-[#160e1d]/95 border-cyan-900/40 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-md bg-cyan-950 border border-cyan-700 text-cyan-400">
                <FileSpreadsheet className="w-4 h-4" />
              </span>
              <h2 className="text-lg font-bold font-mono tracking-wide text-white">
                SOFTWARE INVENTORY, NMAP & NESSUS AUDITOR
              </h2>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl font-sans leading-relaxed">
              Upload your software inventory (Excel <span className="text-cyan-400 font-mono">.xlsx</span>, <span className="text-cyan-400 font-mono">.xls</span> or <span className="text-cyan-400 font-mono">.csv</span>), or directly drop <span className="text-cyan-400 font-mono">Nmap XML (.xml)</span> and <span className="text-cyan-400 font-mono">Nessus (.nessus / .csv)</span> scan reports.
              Our auditor parses all services, open ports, and detected CVEs, correlating them against the live CISA Zero-Day catalog and FIRST.org EPSS exploit predictions.
            </p>
            <div className="mt-3 flex items-center gap-2 flex-wrap text-[11px] font-mono text-slate-400">
              <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                Formats: Excel (.xlsx/.xls) | CSV | Nmap (.xml) | Nessus (.nessus/.csv)
              </span>
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> No Agent / Server Connection Needed
              </span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-3 flex-wrap flex-shrink-0">
            <a
              href="/api/cve/sample-template"
              download="threat_radar_sample_inventory.csv"
              className="px-3.5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-slate-600 text-xs font-mono font-semibold flex items-center gap-2 transition-all shadow-md"
            >
              <Download className="w-4 h-4 text-cyan-400" />
              <span>Download CSV Template</span>
            </a>

            <button
              onClick={handleLoadDemo}
              disabled={loading}
              className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-700 hover:from-cyan-500 hover:to-cyan-600 text-white text-xs font-mono font-bold tracking-wider flex items-center gap-2 shadow-lg shadow-cyan-950/50 transition-all disabled:opacity-50"
            >
              <Sparkles className="w-4 h-4" />
              <span>LOAD DEMO INVENTORY</span>
            </button>
          </div>
        </div>

        {/* Drag and Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`mt-6 border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 ${
            isDragging
              ? 'border-cyan-400 bg-cyan-950/30'
              : 'border-slate-700/80 hover:border-cyan-500/60 bg-slate-950/40 hover:bg-slate-900/40'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".xlsx,.xls,.csv,.xml,.nessus"
            onChange={handleFileChange}
            className="hidden"
          />

          <div className="flex flex-col items-center justify-center">
            <div className="w-12 h-12 rounded-xl bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400 mb-3 shadow-md shadow-cyan-950">
              <UploadCloud className="w-6 h-6 animate-pulse" />
            </div>

            <p className="text-sm font-semibold text-slate-200 font-mono">
              Drop Excel, CSV, Nmap XML (.xml), or Nessus (.nessus) scan here, or{' '}
              <span className="text-cyan-400 underline underline-offset-4">browse files</span>
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Supports files up to 25MB • Automatically detects file type and parses hosts, ports, and CVEs
            </p>
          </div>
        </div>

        {/* Upload error alert */}
        {uploadError && (
          <div className="mt-4 p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>Error: {uploadError}</span>
          </div>
        )}
      </div>

      {/* Loading State */}
      {loading && (
        <div className="cyber-card p-16 text-center flex flex-col items-center justify-center">
          <div className="w-12 h-12 rounded-full border-2 border-cyan-500/40 border-t-cyan-500 animate-spin mb-4" />
          <p className="text-sm font-mono text-slate-300">
            Parsing Spreadsheet & Correlating with CISA KEV Catalog...
          </p>
          <span className="text-xs text-slate-500 mt-1 font-mono">
            Evaluating CVE metrics, CVSS scores, and weaponized zero-day exploits
          </span>
        </div>
      )}

      {/* Audit Dashboard (Only visible when inventory is loaded) */}
      {auditSummary && !loading && (
        <div className="space-y-6">
          {/* KPI Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* KPI 1: Total Assets */}
            <div className="cyber-card p-4 border-slate-800 bg-[#0b0f19]">
              <span className="text-xs font-mono uppercase text-slate-400">Total Scanned Assets</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold font-mono text-white">
                  {auditSummary.totalAssets}
                </span>
                <span className="text-xs font-mono text-slate-400">Entities</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500 truncate">
                File: {auditFilename || 'Uploaded Inventory'}
              </p>
            </div>

            {/* KPI 2: Active Zero-Days Found */}
            <div className="cyber-card p-4 border-rose-900/60 bg-gradient-to-br from-[#1b0811]/90 to-[#0b0f19]/90 relative overflow-hidden">
              <span className="text-xs font-mono uppercase text-rose-400 font-bold">
                Targeted Zero-Days
              </span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold font-mono text-rose-400">
                  {auditSummary.activeZeroDays}
                </span>
                <span className="text-xs font-mono text-rose-400 font-semibold">Immediate Action</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                Matched active CISA KEV catalog entries
              </p>
              <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-rose-600/10 blur-xl pointer-events-none" />
            </div>

            {/* KPI 3: Critical CVE Assets */}
            <div className="cyber-card p-4 border-amber-900/60 bg-gradient-to-br from-[#1a1005]/90 to-[#0b0f19]/90 relative overflow-hidden">
              <span className="text-xs font-mono uppercase text-amber-400 font-bold">
                Critical CVEs (9.0+)
              </span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold font-mono text-amber-400">
                  {auditSummary.criticalAssets}
                </span>
                <span className="text-xs font-mono text-amber-400 font-semibold">High Severity</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                High-impact vulnerabilities requiring patch
              </p>
              <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-amber-600/10 blur-xl pointer-events-none" />
            </div>

            {/* KPI 4: Safe Assets */}
            <div className="cyber-card p-4 border-emerald-900/60 bg-gradient-to-br from-[#061810]/90 to-[#0b0f19]/90 relative overflow-hidden">
              <span className="text-xs font-mono uppercase text-emerald-400 font-bold">
                Safe / Low Risk Assets
              </span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-extrabold font-mono text-emerald-400">
                  {auditSummary.safeAssets}
                </span>
                <span className="text-xs font-mono text-emerald-400 font-semibold">Clean</span>
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                No known exploits in CISA or NVD
              </p>
              <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-emerald-600/10 blur-xl pointer-events-none" />
            </div>
          </div>

          {/* Table Filter & Search Controls */}
          <div className="cyber-card p-4 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search asset, host, or department..."
                className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
              <button
                onClick={() => setTableFilter('all')}
                className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors ${
                  tableFilter === 'all'
                    ? 'bg-slate-700 text-white border border-slate-600'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                All Assets ({auditSummary.results.length})
              </button>

              <button
                onClick={() => setTableFilter('zero-day')}
                className={`px-3 py-1 rounded text-xs font-mono font-medium flex items-center gap-1 transition-colors ${
                  tableFilter === 'zero-day'
                    ? 'bg-rose-950 text-rose-200 border border-rose-700'
                    : 'bg-slate-900 text-rose-400 hover:text-rose-300 border border-slate-800'
                }`}
              >
                <Flame className="w-3 h-3 text-rose-500" />
                Zero-Days ({auditSummary.activeZeroDays})
              </button>

              <button
                onClick={() => setTableFilter('critical')}
                className={`px-3 py-1 rounded text-xs font-mono font-medium flex items-center gap-1 transition-colors ${
                  tableFilter === 'critical'
                    ? 'bg-amber-950 text-amber-200 border border-amber-700'
                    : 'bg-slate-900 text-amber-400 hover:text-amber-300 border border-slate-800'
                }`}
              >
                <AlertTriangle className="w-3 h-3 text-amber-500" />
                Critical ({auditSummary.criticalAssets})
              </button>

              <button
                onClick={() => setTableFilter('safe')}
                className={`px-3 py-1 rounded text-xs font-mono font-medium flex items-center gap-1 transition-colors ${
                  tableFilter === 'safe'
                    ? 'bg-emerald-950 text-emerald-200 border border-emerald-700'
                    : 'bg-slate-900 text-emerald-400 hover:text-emerald-300 border border-slate-800'
                }`}
              >
                <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                Safe Assets ({auditSummary.safeAssets})
              </button>
            </div>
          </div>

          {/* Audit Results Table */}
          <div className="cyber-card overflow-hidden border-slate-800">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                    <th className="py-3 px-4">Software Name & Version</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Host / Workstation</th>
                    <th className="py-3 px-4">Department</th>
                    <th className="py-3 px-4 text-center">Risk Status</th>
                    <th className="py-3 px-4 text-center">CVE Count</th>
                    <th className="py-3 px-4 text-right">Audit Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredResults.map((item, idx) => (
                    <tr
                      key={`${item.asset.softwareName}-${idx}`}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        item.riskStatus === 'ACTIVE ZERO-DAY' ? 'bg-rose-950/10' : ''
                      }`}
                    >
                      {/* Software Name & Version */}
                      <td className="py-3 px-4">
                        <div className="font-bold text-slate-200">
                          {item.asset.softwareName}
                        </div>
                        {item.asset.version ? (
                          <div className="text-[11px] text-slate-400 font-mono">
                            v{item.asset.version}
                          </div>
                        ) : (
                          <div className="text-[11px] text-slate-600">vUnspecified</div>
                        )}
                      </td>

                      {/* Category */}
                      <td className="py-3 px-4 text-slate-300">
                        {item.asset.category || 'Standard Software'}
                      </td>

                      {/* Host / Workstation */}
                      <td className="py-3 px-4 text-slate-300 truncate max-w-xs">
                        <div className="flex items-center gap-1.5">
                          <Server className="w-3 h-3 text-slate-500" />
                          <span className="text-slate-200">{item.asset.host || 'General Endpoint'}</span>
                        </div>
                      </td>

                      {/* Department */}
                      <td className="py-3 px-4 text-slate-300">
                        <div className="flex items-center gap-1.5">
                          <Building className="w-3 h-3 text-slate-500" />
                          <span>{item.asset.department || 'Enterprise Ops'}</span>
                        </div>
                      </td>

                      {/* Risk Status Pill */}
                      <td className="py-3 px-4 text-center">
                        {item.riskStatus === 'ACTIVE ZERO-DAY' && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold uppercase bg-rose-600 text-white shadow-sm shadow-rose-950 animate-pulse">
                            <Flame className="w-3 h-3" />
                            ACTIVE ZERO-DAY
                          </span>
                        )}
                        {item.riskStatus === 'CRITICAL' && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold uppercase bg-amber-600 text-white">
                            <AlertTriangle className="w-3 h-3" />
                            CRITICAL (9.0+)
                          </span>
                        )}
                        {item.riskStatus === 'HIGH' && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold uppercase bg-indigo-900 text-indigo-200 border border-indigo-700">
                            HIGH RISK
                          </span>
                        )}
                        {item.riskStatus === 'SAFE' && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-bold uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">
                            <CheckCircle2 className="w-3 h-3" />
                            SAFE
                          </span>
                        )}
                      </td>

                      {/* Matched CVE Count */}
                      <td className="py-3 px-4 text-center">
                        <span
                          className={`font-bold font-mono px-2 py-0.5 rounded text-xs ${
                            item.totalCveCount > 0
                              ? 'bg-slate-800 text-slate-200 border border-slate-700'
                              : 'text-slate-600'
                          }`}
                        >
                          {item.totalCveCount} CVEs
                        </span>
                      </td>

                      {/* Inspect Button */}
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedAsset(item)}
                          className="px-3 py-1 rounded-md bg-slate-800 hover:bg-indigo-600 text-slate-300 hover:text-white border border-slate-700 hover:border-indigo-500 text-xs font-mono font-medium transition-all inline-flex items-center gap-1.5"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Asset Inspection Drawer */}
      <AssetDrawer
        auditItem={selectedAsset}
        onClose={() => setSelectedAsset(null)}
      />
    </div>
  );
};
