import React from 'react';
import {
  Flame,
  AlertTriangle,
  ExternalLink,
  CheckCircle2,
  Calendar,
  Layers,
  Crosshair,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import { NormalizedCve } from '../types';

interface CveCardProps {
  cve: NormalizedCve;
}

export const CveCard: React.FC<CveCardProps> = ({ cve }) => {
  const isRecentYear =
    cve.publishedDate.includes('2025') ||
    cve.publishedDate.includes('2026') ||
    cve.publishedDate.includes('2024');

  const getCvssColor = (score: number | null) => {
    if (score === null) return 'text-slate-400 bg-slate-800 border-slate-700';
    if (score >= 9.0) return 'text-rose-300 bg-rose-950/80 border-rose-700';
    if (score >= 7.0) return 'text-amber-300 bg-amber-950/80 border-amber-700';
    if (score >= 4.0) return 'text-yellow-300 bg-yellow-950/80 border-yellow-700';
    return 'text-emerald-300 bg-emerald-950/80 border-emerald-700';
  };

  const formattedDate = (() => {
    try {
      const d = new Date(cve.publishedDate);
      return d.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return cve.publishedDate.slice(0, 10);
    }
  })();

  return (
    <div
      className={`cyber-card p-5 relative overflow-hidden transition-all duration-300 ${
        cve.isZeroDay
          ? 'border-rose-900/70 bg-gradient-to-br from-[#130711]/95 to-[#0b0f19]/95 hover:border-rose-600/80 hover:shadow-lg hover:shadow-rose-950/40'
          : 'border-slate-800/80 hover:border-slate-700'
      }`}
    >
      {/* Top Accent Line */}
      <div
        className={`absolute top-0 left-0 right-0 h-[2px] ${
          cve.isZeroDay
            ? 'bg-gradient-to-r from-rose-500 via-rose-600 to-amber-500'
            : 'bg-gradient-to-r from-indigo-500 via-indigo-600 to-cyan-500'
        }`}
      />

      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Exact CVE ID in Monospace */}
          <span className="font-mono font-extrabold text-sm px-2.5 py-1 bg-slate-900 border border-slate-700 rounded-md text-rose-400 tracking-wider">
            {cve.cveId}
          </span>

          {/* Active Zero Day Badge */}
          {cve.isZeroDay && (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-bold font-mono uppercase bg-rose-600 text-white flex items-center gap-1 shadow-md shadow-rose-900/60 animate-pulse-fast">
              <Flame className="w-3.5 h-3.5" />
              Active Zero-Day In The Wild
            </span>
          )}

          {/* Ransomware Badge */}
          {cve.isRansomware && (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-bold font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-600/70 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              Ransomware Weaponized
            </span>
          )}

          {/* Year Badge */}
          <span
            className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold flex items-center gap-1 ${
              isRecentYear
                ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-700'
                : 'bg-slate-900 text-slate-400 border border-slate-800'
            }`}
          >
            <Calendar className="w-3 h-3 text-cyan-400" />
            {formattedDate}
          </span>

          {/* Vendor / Product Pill */}
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800/90 text-slate-300 border border-slate-700 flex items-center gap-1">
            <Layers className="w-3 h-3 text-indigo-400" />
            <strong className="text-white">{cve.vendor}</strong> : {cve.product}
          </span>
        </div>

        {/* CVSS & EPSS Score Gauges */}
        <div className="flex items-center gap-2">
          {cve.epssScore !== undefined && cve.epssScore !== null && (
            <span
              className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold border flex items-center gap-1 ${
                cve.epssScore >= 0.7
                  ? 'bg-rose-950/80 text-rose-300 border-rose-700'
                  : cve.epssScore >= 0.3
                  ? 'bg-amber-950/80 text-amber-300 border-amber-700'
                  : 'bg-cyan-950/80 text-cyan-300 border-cyan-700'
              }`}
              title={`FIRST.org EPSS Exploit Probability: ${(cve.epssScore * 100).toFixed(1)}% within 30 days`}
            >
              <Zap className="w-3 h-3 text-cyan-400" />
              <span>EPSS {(cve.epssScore * 100).toFixed(1)}%</span>
            </span>
          )}

          <div
            className={`px-3 py-1 rounded-md text-xs font-mono font-bold border flex items-center gap-1.5 ${getCvssColor(
              cve.cvssScore
            )}`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>
              {cve.severity} {cve.cvssScore !== null ? cve.cvssScore.toFixed(1) : 'N/A'}
            </span>
          </div>
        </div>
      </div>

      {/* Title */}
      <h3 className="text-base font-semibold text-slate-100 mb-2 leading-snug">
        {cve.title}
      </h3>

      {/* Description */}
      <p className="text-xs text-slate-300 leading-relaxed mb-3">
        {cve.description}
      </p>

      {/* Attack Vector & Due Date */}
      <div className="flex flex-wrap items-center gap-4 mb-3 text-[11px] font-mono text-slate-400">
        {cve.attackVector && (
          <div className="flex items-center gap-1.5">
            <Crosshair className="w-3 h-3 text-rose-400" />
            <span>Vector:</span>
            <span className="text-slate-200 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              {cve.attackVector}
            </span>
          </div>
        )}

        {cve.dueDate && (
          <div className="flex items-center gap-1.5 text-amber-400">
            <Calendar className="w-3 h-3" />
            <span>CISA Due Date:</span>
            <span className="bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/60 font-bold">
              {cve.dueDate}
            </span>
          </div>
        )}
      </div>

      {/* Emerald Mitigation Box */}
      <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs mb-3 flex items-start gap-2.5">
        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <div className="font-semibold text-emerald-400 uppercase tracking-wider text-[10px] mb-0.5 font-mono">
            Remediation & Patch Guidance:
          </div>
          <div className="text-emerald-200 leading-normal">
            {cve.requiredAction || cve.remediation || 'Apply vendor security updates immediately.'}
          </div>
        </div>
      </div>

      {/* External References */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-slate-500 font-mono text-[11px]">NVD / Advisories:</span>
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300 font-mono text-[11px] hover:underline"
          >
            <span>NVD Page</span>
            <ExternalLink className="w-3 h-3" />
          </a>

          {cve.isCisaKev && (
            <a
              href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve.cveId}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-rose-400 hover:text-rose-300 font-mono text-[11px] hover:underline"
            >
              <span>CISA KEV Page</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>

        {cve.references && cve.references.length > 0 && (
          <a
            href={cve.references[0]}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-slate-400 hover:text-white text-[11px] hover:underline"
          >
            <span>Primary Reference</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
    </div>
  );
};
