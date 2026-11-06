import React from 'react';
import {
  X,
  ShieldAlert,
  Flame,
  AlertTriangle,
  CheckCircle2,
  Server,
  Layers,
  Building,
  ExternalLink,
  Crosshair,
  Zap,
} from 'lucide-react';
import { AssetAuditResult } from '../types';

interface AssetDrawerProps {
  auditItem: AssetAuditResult | null;
  onClose: () => void;
}

export const AssetDrawer: React.FC<AssetDrawerProps> = ({ auditItem, onClose }) => {
  if (!auditItem) return null;

  const { asset, riskStatus, highestCvss, zeroDayCount, matchedCves } = auditItem;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/70 backdrop-blur-sm flex justify-end">
      {/* Backdrop click */}
      <div className="absolute inset-0" onClick={onClose} />

      {/* Drawer Container */}
      <div className="relative w-full max-w-2xl bg-[#090d18] border-l border-slate-800 shadow-2xl flex flex-col h-full overflow-hidden z-10 animate-in slide-in-from-right duration-200">
        {/* Drawer Header */}
        <div className="p-5 border-b border-slate-800 bg-[#060a14] flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono uppercase text-slate-400">
                ASSET AUDIT INSPECTION
              </span>
              {riskStatus === 'ACTIVE ZERO-DAY' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-600 text-white flex items-center gap-1 shadow-md shadow-rose-950 animate-pulse">
                  <Flame className="w-3 h-3" />
                  ACTIVE ZERO-DAY
                </span>
              )}
              {riskStatus === 'CRITICAL' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-600 text-white flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  CRITICAL RISK
                </span>
              )}
              {riskStatus === 'SAFE' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-600 text-white flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" />
                  SAFE ASSET
                </span>
              )}
            </div>

            <h2 className="text-xl font-bold font-mono text-white flex items-center gap-2">
              {asset.softwareName}
              {asset.version && (
                <span className="text-sm font-normal text-slate-400 font-mono">
                  v{asset.version}
                </span>
              )}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Asset Meta Details */}
        <div className="p-5 bg-slate-950/60 border-b border-slate-800/80 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Category</span>
            <span className="text-slate-200 font-semibold">{asset.category || 'Standard Software'}</span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Department / Owner</span>
            <span className="text-slate-200 font-semibold">{asset.department || 'Enterprise Ops'}</span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 col-span-2 sm:col-span-1">
            <span className="text-slate-500 block text-[10px] uppercase">Host / Workstation</span>
            <span className="text-slate-200 font-semibold truncate block">{asset.host || 'General Endpoint'}</span>
          </div>
        </div>

        {/* Drawer Body: Correlated Vulnerabilities */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>Correlated Vulnerabilities ({matchedCves.length})</span>
            </h3>

            {highestCvss > 0 && (
              <span className="text-xs font-mono text-slate-400">
                Peak CVSS: <strong className="text-rose-400">{highestCvss.toFixed(1)}</strong>
              </span>
            )}
          </div>

          {matchedCves.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800 text-center">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
              <h4 className="text-sm font-semibold text-slate-200 font-mono">
                No Known Active Zero-Days or Critical Exploits Found
              </h4>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                This asset version is not currently listed in the active CISA KEV catalog or critical vulnerability alerts.
              </p>
            </div>
          ) : (
            matchedCves.map((cve) => (
              <div
                key={cve.cveId}
                className={`p-4 rounded-xl border text-xs ${
                  cve.isZeroDay
                    ? 'bg-rose-950/20 border-rose-800/80'
                    : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-rose-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-700">
                      {cve.cveId}
                    </span>
                    {cve.isZeroDay && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-bold font-mono uppercase bg-rose-600 text-white flex items-center gap-1">
                        <Flame className="w-2.5 h-2.5" />
                        CISA Zero-Day
                      </span>
                    )}
                    {cve.isRansomware && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-bold font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-600">
                        Ransomware
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {cve.epssScore !== undefined && cve.epssScore !== null && (
                      <span className="px-2 py-0.5 rounded font-mono font-bold text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-700 flex items-center gap-1">
                        <Zap className="w-2.5 h-2.5" />
                        EPSS {(cve.epssScore * 100).toFixed(1)}%
                      </span>
                    )}

                    <span
                      className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                        (cve.cvssScore ?? 0) >= 9.0
                          ? 'bg-rose-900 text-rose-200 border border-rose-700'
                          : 'bg-amber-900 text-amber-200 border border-amber-700'
                      }`}
                    >
                      CVSS {cve.cvssScore !== null ? cve.cvssScore.toFixed(1) : '9.8'}
                    </span>
                  </div>
                </div>

                <h4 className="font-semibold text-slate-100 mb-1 text-sm">
                  {cve.title}
                </h4>

                <p className="text-slate-300 leading-relaxed mb-3">
                  {cve.description}
                </p>

                {cve.attackVector && (
                  <div className="flex items-center gap-1.5 mb-2 font-mono text-[11px] text-slate-400">
                    <Crosshair className="w-3 h-3 text-rose-400" />
                    <span>Vector:</span>
                    <span className="text-slate-200">{cve.attackVector}</span>
                  </div>
                )}

                {/* Emerald Remediation */}
                <div className="p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-[11px] flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold uppercase font-mono block text-[10px] text-emerald-400">
                      Required Action:
                    </span>
                    <span>{cve.requiredAction || cve.remediation || 'Upgrade software to latest vendor patch.'}</span>
                  </div>
                </div>

                <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-end">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300 font-mono text-[11px] hover:underline"
                  >
                    <span>View NIST NVD Advisory</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#060a14] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium transition-colors"
          >
            Close Inspection Drawer
          </button>
        </div>
      </div>
    </div>
  );
};
