import React, { useState, useEffect, useMemo } from 'react';
import {
  Search,
  BookOpen,
  Filter,
  Flame,
  AlertTriangle,
  Zap,
  RotateCcw,
  Compass,
  Layers,
} from 'lucide-react';
import { NormalizedCve } from '../types';
import { threatApi } from '../services/api';
import { CveCard } from './CveCard';

const POPULAR_TARGETS = [
  'Telegram',
  'Nginx',
  'OpenSSH',
  'Fortinet',
  'Windows',
  'WordPress',
  'Cisco',
  'Redis',
  'Docker',
  'Chrome',
];

interface EncyclopediaTabProps {
  initialQuery?: string;
}

type FilterOption = 'all' | 'recent' | 'zero-day' | 'critical';

export const EncyclopediaTab: React.FC<EncyclopediaTabProps> = ({
  initialQuery = '',
}) => {
  const [searchTerm, setSearchTerm] = useState(initialQuery);
  const [results, setResults] = useState<NormalizedCve[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeFilter, setActiveFilter] = useState<FilterOption>('all');
  const [totalFound, setTotalFound] = useState<number>(0);
  const [searchedKeyword, setSearchedKeyword] = useState<string>('');

  const executeSearch = async (query: string) => {
    setLoading(true);
    setSearchedKeyword(query);
    try {
      const data = await threatApi.searchCves(query, 25);
      setResults(data.results || []);
      setTotalFound(data.count || 0);
    } catch (err) {
      console.error('Failed to search CVEs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    executeSearch(initialQuery);
  }, [initialQuery]);

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchTerm.trim()) {
      executeSearch(searchTerm.trim());
    }
  };

  const handleQuickPill = (target: string) => {
    setSearchTerm(target);
    executeSearch(target);
  };

  const filteredResults = useMemo(() => {
    return results.filter((cve) => {
      if (activeFilter === 'zero-day' && !cve.isZeroDay && !cve.isCisaKev) return false;
      if (activeFilter === 'critical' && (cve.cvssScore ?? 0) < 9.0 && cve.severity !== 'CRITICAL') return false;
      if (activeFilter === 'recent') {
        const isRecent =
          cve.publishedDate.includes('2025') ||
          cve.publishedDate.includes('2026') ||
          cve.publishedDate.includes('2024');
        if (!isRecent) return false;
      }
      return true;
    });
  }, [results, activeFilter]);

  return (
    <div className="space-y-6">
      {/* Search Header Banner */}
      <div className="cyber-card p-6 bg-gradient-to-br from-[#0c0f1d]/95 via-[#0b0f19]/95 to-[#120a1c]/95 border-indigo-900/40 relative overflow-hidden">
        <div className="relative z-10">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-md bg-indigo-950 border border-indigo-700 text-indigo-400">
                <BookOpen className="w-4 h-4" />
              </span>
              <h2 className="text-lg font-bold font-mono tracking-wide text-white">
                CVE ENCYCLOPEDIA & SOFTWARE DICTIONARY
              </h2>
            </div>

            {/* Smart Tail Indicator Badge */}
            <div className="px-2.5 py-1 rounded-md bg-indigo-950/80 border border-indigo-700 text-indigo-300 text-xs font-mono flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>NVD Smart Tail Engine (2025–2026 Newest First)</span>
            </div>
          </div>

          <p className="text-xs text-slate-400 max-w-2xl mb-4 font-sans">
            Search live vulnerability intelligence across the NIST National Vulnerability Database (250,000+ CVEs)
            and CISA Known Exploited Catalog with automatic reverse tail sorting and active zero-day correlation.
          </p>

          {/* Search Input Bar */}
          <form onSubmit={handleFormSubmit} className="relative flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-5 h-5 text-indigo-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search software (Telegram, Nginx, OpenSSH, Cisco, Fortinet...) or exact CVE-YYYY-NNNN..."
                className="w-full pl-11 pr-24 py-3 bg-[#030712] border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all shadow-inner"
              />
              {searchTerm && (
                <button
                  type="button"
                  onClick={() => setSearchTerm('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-mono text-slate-400 hover:text-white px-1.5 py-0.5 rounded bg-slate-800"
                >
                  Clear
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white rounded-lg text-xs font-bold font-mono tracking-wider flex items-center gap-2 shadow-lg shadow-indigo-950/50 transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  <span>SEARCHING...</span>
                </>
              ) : (
                <>
                  <Compass className="w-4 h-4" />
                  <span>SEARCH RADAR</span>
                </>
              )}
            </button>
          </form>

          {/* Popular Target Quick Pills */}
          <div className="mt-4 flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1">
              <Layers className="w-3 h-3 text-indigo-400" />
              Popular Targets:
            </span>
            {POPULAR_TARGETS.map((target) => (
              <button
                key={target}
                onClick={() => handleQuickPill(target)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition-all ${
                  searchedKeyword.toLowerCase() === target.toLowerCase()
                    ? 'bg-indigo-600 text-white border border-indigo-400 font-bold shadow-sm shadow-indigo-950'
                    : 'bg-slate-900/90 text-slate-300 hover:text-white hover:bg-slate-800 border border-slate-800'
                }`}
              >
                {target}
              </button>
            ))}
          </div>
        </div>

        {/* Ambient Glow */}
        <div className="absolute -top-12 -right-12 w-48 h-48 rounded-full bg-indigo-600/10 blur-3xl pointer-events-none" />
      </div>

      {/* Filter Tabs & Stats Bar */}
      <div className="cyber-card p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            Filters:
          </span>

          <button
            onClick={() => setActiveFilter('all')}
            className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors ${
              activeFilter === 'all'
                ? 'bg-slate-700 text-white border border-slate-600'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            All Results ({results.length})
          </button>

          <button
            onClick={() => setActiveFilter('recent')}
            className={`px-3 py-1 rounded text-xs font-mono font-medium transition-colors ${
              activeFilter === 'recent'
                ? 'bg-cyan-950 text-cyan-200 border border-cyan-700'
                : 'bg-slate-900 text-cyan-400 hover:text-cyan-300 border border-slate-800'
            }`}
          >
            Recent (2025–2026)
          </button>

          <button
            onClick={() => setActiveFilter('zero-day')}
            className={`px-3 py-1 rounded text-xs font-mono font-medium flex items-center gap-1 transition-colors ${
              activeFilter === 'zero-day'
                ? 'bg-rose-950 text-rose-200 border border-rose-700 shadow-sm shadow-rose-950'
                : 'bg-slate-900 text-rose-400 hover:text-rose-300 border border-slate-800'
            }`}
          >
            <Flame className="w-3 h-3 text-rose-500" />
            Zero-Days (CISA KEV)
          </button>

          <button
            onClick={() => setActiveFilter('critical')}
            className={`px-3 py-1 rounded text-xs font-mono font-medium flex items-center gap-1 transition-colors ${
              activeFilter === 'critical'
                ? 'bg-amber-950 text-amber-200 border border-amber-700'
                : 'bg-slate-900 text-amber-400 hover:text-amber-300 border border-slate-800'
            }`}
          >
            <AlertTriangle className="w-3 h-3 text-amber-500" />
            Critical (9.0+)
          </button>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-indigo-400 font-bold">{filteredResults.length}</span> vulnerabilities
          {searchedKeyword && (
            <span>
              {' '}
              for <strong className="text-white">"{searchedKeyword}"</strong>
            </span>
          )}
        </div>
      </div>

      {/* Results View */}
      {loading ? (
        <div className="cyber-card p-16 text-center flex flex-col items-center justify-center">
          <div className="relative w-16 h-16 mb-4">
            <div className="absolute inset-0 rounded-full border-2 border-indigo-500/30 border-t-indigo-500 animate-spin" />
            <div className="absolute inset-3 rounded-full border-2 border-rose-500/30 border-b-rose-500 animate-spin" style={{ animationDirection: 'reverse' }} />
          </div>
          <p className="text-sm font-mono text-slate-300">
            Smart Tail Fetching from NIST NVD 2.0 & CISA Catalog...
          </p>
          <span className="text-xs text-slate-500 mt-1 font-mono">
            Querying total results count & calculating ascending tail index
          </span>
        </div>
      ) : filteredResults.length === 0 ? (
        <div className="cyber-card p-16 text-center">
          <BookOpen className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-300 font-mono">
            No CVE records found
          </h3>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            Try searching for common enterprise software like "Fortinet", "OpenSSH", "Telegram", "Windows", or click one of the quick pills above.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredResults.map((cve) => (
            <CveCard key={cve.cveId} cve={cve} />
          ))}
        </div>
      )}
    </div>
  );
};
