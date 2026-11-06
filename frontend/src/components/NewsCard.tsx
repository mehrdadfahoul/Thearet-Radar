import React from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  ExternalLink,
  CheckCircle2,
  Calendar,
  Layers,
  Crosshair,
  Zap,
} from 'lucide-react';
import { UnifiedThreatNews } from '../types';

interface NewsCardProps {
  news: UnifiedThreatNews;
  onInspectCve?: (cveId: string) => void;
}

export const NewsCard: React.FC<NewsCardProps> = ({ news, onInspectCve }) => {
  const getSeverityBadge = () => {
    const score = news.cvssScore !== null ? news.cvssScore.toFixed(1) : 'N/A';
    if (news.severity === 'CRITICAL' || (news.cvssScore ?? 0) >= 9.0) {
      return (
        <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-700/80 flex items-center gap-1 shadow-sm shadow-rose-950/50">
          <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
          CRITICAL {score}
        </span>
      );
    }
    if (news.severity === 'HIGH' || (news.cvssScore ?? 0) >= 7.0) {
      return (
        <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700/80 flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-amber-500" />
          HIGH {score}
        </span>
      );
    }
    return (
      <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
        MEDIUM {score}
      </span>
    );
  };

  return (
    <div
      className={`cyber-card p-5 relative overflow-hidden transition-all duration-300 ${
        news.isZeroDay
          ? 'border-rose-900/60 bg-gradient-to-br from-[#120710]/95 to-[#0b0f19]/95 hover:border-rose-600/70 hover:shadow-lg hover:shadow-rose-950/40'
          : 'border-slate-800/80 hover:border-slate-700'
      }`}
    >
      {/* Decorative top accent line */}
      <div
        className={`absolute top-0 left-0 right-0 h-[2px] ${
          news.isZeroDay
            ? 'bg-gradient-to-r from-rose-500 via-rose-600 to-amber-500'
            : 'bg-gradient-to-r from-indigo-500 to-cyan-500'
        }`}
      />

      {/* Top Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          {/* Active Zero Day In The Wild Badge */}
          {news.isZeroDay && (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-bold font-mono uppercase bg-rose-600 text-white flex items-center gap-1 shadow-md shadow-rose-900/60 animate-pulse-fast">
              <Flame className="w-3.5 h-3.5" />
              Active Zero-Day In The Wild
            </span>
          )}

          {/* Ransomware Target Badge */}
          {news.isRansomware && (
            <span className="px-2.5 py-0.5 rounded text-[11px] font-bold font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-600/70 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              {news.ransomwareCampaign || 'Ransomware Target'}
            </span>
          )}

          {/* Source Tag */}
          {news.isCisaKev ? (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-rose-950/60 text-rose-300 border border-rose-800">
              CISA KEV Catalog
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-950/60 text-cyan-300 border border-cyan-800">
              GitHub Advisory
            </span>
          )}

          {/* Affected Entity Pill */}
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1">
            <Layers className="w-3 h-3 text-indigo-400" />
            <strong className="text-white">{news.vendor}</strong> : {news.product}
          </span>
        </div>

        {/* Severity & EPSS Pills */}
        <div className="flex items-center gap-2">
          {news.epssScore !== undefined && news.epssScore !== null && (
            <span
              className={`px-2 py-1 rounded-md text-xs font-mono font-bold border flex items-center gap-1 ${
                news.epssScore >= 0.7
                  ? 'bg-rose-950/80 text-rose-300 border-rose-700'
                  : news.epssScore >= 0.3
                  ? 'bg-amber-950/80 text-amber-300 border-amber-700'
                  : 'bg-cyan-950/80 text-cyan-300 border-cyan-700'
              }`}
              title={`EPSS Exploit Prediction: ${(news.epssScore * 100).toFixed(1)}% probability of active exploitation in 30 days`}
            >
              <Zap className="w-3 h-3 text-cyan-400" />
              EPSS {(news.epssScore * 100).toFixed(1)}%
            </span>
          )}
          {getSeverityBadge()}
        </div>
      </div>

      {/* Title & CVE ID */}
      <div className="mb-2.5">
        <div className="flex items-center gap-2 mb-1">
          {news.cveId && (
            <button
              onClick={() => onInspectCve?.(news.cveId!)}
              className="text-xs font-mono font-bold text-rose-400 hover:text-rose-300 hover:underline bg-rose-950/50 px-2 py-0.5 rounded border border-rose-800/60 transition-colors"
              title="Click to search in CVE Encyclopedia"
            >
              {news.cveId}
            </button>
          )}
          <span className="text-xs text-slate-400 flex items-center gap-1 font-mono">
            <Calendar className="w-3 h-3 text-slate-500" />
            {news.humanizedDate}
          </span>
        </div>

        <h3 className="text-base font-semibold text-slate-100 leading-snug group-hover:text-rose-200">
          {news.title}
        </h3>
      </div>

      {/* Threat Summary */}
      <p className="text-xs text-slate-300 leading-relaxed mb-3 line-clamp-3">
        {news.summary}
      </p>

      {/* Attack Vector & Meta */}
      {news.attackVector && (
        <div className="flex items-center gap-2 mb-3 text-[11px] text-slate-400 font-mono">
          <Crosshair className="w-3 h-3 text-rose-400" />
          <span>Attack Vector:</span>
          <span className="text-slate-200 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
            {news.attackVector}
          </span>
        </div>
      )}

      {/* Emerald Mitigation Box */}
      <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs mb-3 flex items-start gap-2.5">
        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <div className="font-semibold text-emerald-400 uppercase tracking-wider text-[10px] mb-0.5 font-mono">
            Required Action / Remediation Instructions:
          </div>
          <div className="text-emerald-200 leading-normal">
            {news.requiredAction || 'Apply the latest security updates and review vendor advisories immediately.'}
          </div>
        </div>
      </div>

      {/* Footer Actions */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
        <span className="text-slate-500 font-mono text-[11px]">
          ID: {news.id}
        </span>

        <div className="flex items-center gap-3">
          {news.cveId && (
            <button
              onClick={() => onInspectCve?.(news.cveId!)}
              className="text-indigo-400 hover:text-indigo-300 font-mono font-medium hover:underline text-[11px]"
            >
              Analyze in Encyclopedia &rarr;
            </button>
          )}

          <a
            href={news.bulletinUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-slate-400 hover:text-white font-medium hover:underline transition-colors"
          >
            <span>Official Bulletin</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>
    </div>
  );
};
