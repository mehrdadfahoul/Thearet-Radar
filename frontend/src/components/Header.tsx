import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Radio,
  Clock,
  Database,
  Cpu,
  Newspaper,
  BookOpen,
  FileSpreadsheet,
  Crosshair,
  Bell,
} from 'lucide-react';
import { HealthStatus } from '../types';

export type ActiveTabType = 'news' | 'encyclopedia' | 'audit' | 'hunter' | 'alerts';

interface HeaderProps {
  activeTab: ActiveTabType;
  setActiveTab: (tab: ActiveTabType) => void;
  health: HealthStatus | null;
  zeroDayCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  health,
  zeroDayCount,
}) => {
  const [utcTime, setUtcTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(
        now.toUTCString().replace('GMT', 'UTC')
      );
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const kevCount = health?.feeds?.cisaKev?.count || 1748;

  return (
    <header className="border-b border-slate-800 bg-[#060a14]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Top Status HUD */}
        <div className="py-2 border-b border-slate-800/60 flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 gap-2">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-semibold text-slate-300">CISA KEV:</span>
              <span className="text-emerald-400 font-bold">{kevCount.toLocaleString()} Exploited Zero-Days</span>
            </div>

            <div className="flex items-center gap-1.5 text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-semibold text-slate-300">GHSA:</span>
              <span className="text-cyan-400 font-bold">Live Stream (10m Sync)</span>
            </div>

            <div className="flex items-center gap-1.5 text-indigo-400 hidden md:flex">
              <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
              <span className="font-semibold text-slate-300">FIRST.org EPSS:</span>
              <span className="text-indigo-400 font-bold">Exploit Prediction AI</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 text-slate-400">
              <Clock className="w-3.5 h-3.5 text-rose-400" />
              <span>{utcTime || 'UTC 00:00:00'}</span>
            </div>
            <div className="bg-rose-950/60 border border-rose-800/80 text-rose-300 px-2 py-0.5 rounded text-[11px] font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
              DEFCON 2
            </div>
          </div>
        </div>

        {/* Main Branding & Navigation */}
        <div className="py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-11 h-11 rounded-lg bg-gradient-to-br from-rose-950 to-slate-900 border border-rose-600/40 text-rose-400 shadow-lg shadow-rose-950/50">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
              <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-rose-500 animate-ping" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-extrabold tracking-wider bg-gradient-to-r from-rose-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent font-mono">
                  THREAT RADAR
                </span>
                <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-widest bg-slate-800 text-slate-300 border border-slate-700 rounded">
                  v2.5 Enterprise
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans">
                Real-Time Cyber Threat Intelligence, CVE Radar & Threat Hunter
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1.5 p-1 bg-slate-900/90 border border-slate-800 rounded-lg flex-wrap">
            <button
              onClick={() => setActiveTab('news')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeTab === 'news'
                  ? 'bg-gradient-to-r from-rose-600 to-rose-700 text-white shadow-md shadow-rose-900/40 border border-rose-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Newspaper className="w-3.5 h-3.5" />
              <span>Live Newsroom</span>
              {zeroDayCount > 0 && (
                <span className="ml-1 px-1.5 py-0.2 bg-rose-900/90 text-rose-200 rounded-full text-[10px] font-mono border border-rose-700">
                  {zeroDayCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('encyclopedia')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeTab === 'encyclopedia'
                  ? 'bg-gradient-to-r from-indigo-600 to-indigo-700 text-white shadow-md shadow-indigo-900/40 border border-indigo-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>CVE Encyclopedia</span>
            </button>

            <button
              onClick={() => setActiveTab('audit')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeTab === 'audit'
                  ? 'bg-gradient-to-r from-cyan-600 to-cyan-700 text-white shadow-md shadow-cyan-900/40 border border-cyan-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>Auditor (Excel/Nmap/Nessus)</span>
            </button>

            <button
              onClick={() => setActiveTab('hunter')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeTab === 'hunter'
                  ? 'bg-gradient-to-r from-purple-600 to-purple-700 text-white shadow-md shadow-purple-900/40 border border-purple-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5" />
              <span>IOC & Threat Hunter</span>
            </button>

            <button
              onClick={() => setActiveTab('alerts')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                activeTab === 'alerts'
                  ? 'bg-gradient-to-r from-emerald-600 to-emerald-700 text-white shadow-md shadow-emerald-900/40 border border-emerald-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Bell className="w-3.5 h-3.5" />
              <span>Alerts (Teams/Email)</span>
            </button>
          </nav>
        </div>
      </div>
    </header>
  );
};
