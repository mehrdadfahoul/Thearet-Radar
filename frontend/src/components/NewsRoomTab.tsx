import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Radio,
  Search,
  Filter,
  RefreshCw,
  TrendingUp,
  Database,
} from 'lucide-react';
import { UnifiedThreatNews, NewsStats } from '../types';
import { NewsCard } from './NewsCard';

interface NewsRoomTabProps {
  newsItems: UnifiedThreatNews[];
  stats: NewsStats | null;
  loading: boolean;
  onRefresh: () => void;
  onInspectCve: (cveId: string) => void;
}

type FilterMode = 'all' | 'zero-day' | 'critical' | 'ransomware';

export const NewsRoomTab: React.FC<NewsRoomTabProps> = ({
  newsItems,
  stats,
  loading,
  onRefresh,
  onInspectCve,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState<FilterMode>('all');

  const filteredNews = useMemo(() => {
    return newsItems.filter((item) => {
      // Filter mode condition
      if (filterMode === 'zero-day' && !item.isZeroDay) return false;
      if (filterMode === 'critical' && (item.cvssScore ?? 0) < 9.0 && item.severity !== 'CRITICAL') return false;
      if (filterMode === 'ransomware' && !item.isRansomware) return false;

      // Search query condition
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase().trim();
      return (
        item.title.toLowerCase().includes(q) ||
        item.summary.toLowerCase().includes(q) ||
        item.vendor.toLowerCase().includes(q) ||
        item.product.toLowerCase().includes(q) ||
        (item.cveId && item.cveId.toLowerCase().includes(q)) ||
        item.id.toLowerCase().includes(q)
      );
    });
  }, [newsItems, filterMode, searchQuery]);

  return (
    <div className="space-y-6">
      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Active Zero Days */}
        <div className="cyber-card p-4 border-rose-900/60 bg-gradient-to-br from-[#1c0812]/90 to-[#0b0f19]/90 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-rose-400">
              Active Zero-Days
            </span>
            <div className="w-8 h-8 rounded-lg bg-rose-950 border border-rose-700/60 flex items-center justify-center text-rose-400">
              <Flame className="w-4 h-4 animate-pulse" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-white">
              {stats?.activeZeroDaysCount ?? 20}
            </span>
            <span className="text-[11px] font-mono text-rose-400 uppercase font-semibold">
              In The Wild
            </span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            Actively exploited by advanced threat actors
          </p>
          <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-rose-600/10 blur-xl pointer-events-none" />
        </div>

        {/* KPI 2: Ransomware Targets */}
        <div className="cyber-card p-4 border-amber-900/60 bg-gradient-to-br from-[#1a1005]/90 to-[#0b0f19]/90 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400">
              Ransomware Targets
            </span>
            <div className="w-8 h-8 rounded-lg bg-amber-950 border border-amber-700/60 flex items-center justify-center text-amber-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-white">
              {stats?.ransomwareTargetsCount ?? 14}
            </span>
            <span className="text-[11px] font-mono text-amber-400 uppercase font-semibold">
              Campaigns
            </span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            Known weaponization in extortion attacks
          </p>
          <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-amber-600/10 blur-xl pointer-events-none" />
        </div>

        {/* KPI 3: CISA KEV Catalog */}
        <div className="cyber-card p-4 border-indigo-900/60 bg-gradient-to-br from-[#0c0d1c]/90 to-[#0b0f19]/90 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-indigo-400">
              CISA KEV Catalog
            </span>
            <div className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-700/60 flex items-center justify-center text-indigo-400">
              <Database className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-white">
              {(stats?.totalCisaKev ?? 1748).toLocaleString()}
            </span>
            <span className="text-[11px] font-mono text-indigo-400 uppercase font-semibold">
              Verified
            </span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            Auto-synced every 6 hours from CISA.gov
          </p>
          <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-indigo-600/10 blur-xl pointer-events-none" />
        </div>

        {/* KPI 4: Stream Feed Velocity */}
        <div className="cyber-card p-4 border-cyan-900/60 bg-gradient-to-br from-[#05141c]/90 to-[#0b0f19]/90 relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Live Threat Feed
            </span>
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/60 flex items-center justify-center text-cyan-400">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-white">
              {newsItems.length}
            </span>
            <span className="text-[11px] font-mono text-cyan-400 uppercase font-semibold">
              Dispatched
            </span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            Real-time GitHub Advisories & CISA KEV
          </p>
          <div className="absolute -bottom-6 -right-6 w-20 h-20 rounded-full bg-cyan-600/10 blur-xl pointer-events-none" />
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="cyber-card p-4 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search input */}
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter news by CVE, vendor, or keyword..."
            className="w-full pl-10 pr-4 py-2 bg-slate-900/90 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 font-mono transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          )}
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
          <button
            onClick={() => setFilterMode('all')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium font-mono transition-all ${
              filterMode === 'all'
                ? 'bg-slate-700 text-white border border-slate-600'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            All News ({newsItems.length})
          </button>

          <button
            onClick={() => setFilterMode('zero-day')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium font-mono flex items-center gap-1.5 transition-all ${
              filterMode === 'zero-day'
                ? 'bg-rose-900 text-rose-100 border border-rose-600 shadow-sm shadow-rose-950'
                : 'bg-slate-900 text-rose-400 hover:text-rose-300 border border-slate-800'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-rose-500" />
            Active Zero-Days
          </button>

          <button
            onClick={() => setFilterMode('critical')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium font-mono flex items-center gap-1.5 transition-all ${
              filterMode === 'critical'
                ? 'bg-amber-900 text-amber-100 border border-amber-600'
                : 'bg-slate-900 text-amber-400 hover:text-amber-300 border border-slate-800'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
            Critical (9.0+)
          </button>

          <button
            onClick={() => setFilterMode('ransomware')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium font-mono flex items-center gap-1.5 transition-all ${
              filterMode === 'ransomware'
                ? 'bg-purple-900 text-purple-100 border border-purple-600'
                : 'bg-slate-900 text-purple-400 hover:text-purple-300 border border-slate-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
            Ransomware Targets
          </button>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-md bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-colors disabled:opacity-50"
            title="Refresh feeds"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* News Feed List */}
      {loading && newsItems.length === 0 ? (
        <div className="cyber-card p-12 text-center flex flex-col items-center justify-center">
          <div className="w-12 h-12 rounded-full border-2 border-rose-500/40 border-t-rose-500 animate-spin mb-4" />
          <p className="text-sm font-mono text-slate-300">
            Intercepting Global Security Advisories & CISA KEV Feeds...
          </p>
        </div>
      ) : filteredNews.length === 0 ? (
        <div className="cyber-card p-12 text-center">
          <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-300 font-mono">
            No threat bulletins matching criteria
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            Try adjusting your search query or reset filter to "All News".
          </p>
          <button
            onClick={() => {
              setSearchQuery('');
              setFilterMode('all');
            }}
            className="mt-4 px-3 py-1.5 rounded-md bg-slate-800 text-slate-300 hover:text-white text-xs font-mono"
          >
            Reset Filters
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredNews.map((news) => (
            <NewsCard key={news.id} news={news} onInspectCve={onInspectCve} />
          ))}
        </div>
      )}
    </div>
  );
};
