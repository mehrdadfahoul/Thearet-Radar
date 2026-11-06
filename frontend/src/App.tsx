import React, { useState, useEffect } from 'react';
import { Header, ActiveTabType } from './components/Header';
import { Ticker } from './components/Ticker';
import { NewsRoomTab } from './components/NewsRoomTab';
import { EncyclopediaTab } from './components/EncyclopediaTab';
import { AssetScannerTab } from './components/AssetScannerTab';
import { ThreatHunterTab } from './components/ThreatHunterTab';
import { AlertsTab } from './components/AlertsTab';
import { threatApi } from './services/api';
import { UnifiedThreatNews, NewsStats, TickerItem, HealthStatus } from './types';

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTabType>('news');
  const [newsFeed, setNewsFeed] = useState<UnifiedThreatNews[]>([]);
  const [newsStats, setNewsStats] = useState<NewsStats | null>(null);
  const [tickerItems, setTickerItems] = useState<TickerItem[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loadingNews, setLoadingNews] = useState(true);
  const [encyclopediaQuery, setEncyclopediaQuery] = useState<string>('');

  const loadData = async () => {
    setLoadingNews(true);
    try {
      const [newsData, tickerData, healthData] = await Promise.all([
        threatApi.getNewsFeed(),
        threatApi.getTicker(),
        threatApi.getHealth().catch(() => null),
      ]);

      setNewsFeed(newsData.feed || []);
      setNewsStats(newsData.stats || null);
      setTickerItems(tickerData || []);
      if (healthData) setHealth(healthData);
    } catch (err) {
      console.error('Failed to load threat data:', err);
    } finally {
      setLoadingNews(false);
    }
  };

  useEffect(() => {
    loadData();
    // Auto-refresh feed every 5 minutes in UI
    const timer = setInterval(loadData, 5 * 60 * 1000);
    return () => clearInterval(timer);
  }, []);

  const handleInspectCve = (cveId: string) => {
    setEncyclopediaQuery(cveId);
    setActiveTab('encyclopedia');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#030712] text-slate-100 selection:bg-rose-500 selection:text-white">
      {/* Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        health={health}
        zeroDayCount={newsStats?.activeZeroDaysCount || 0}
      />

      {/* Breaking Threats Ticker */}
      <Ticker items={tickerItems} onSelectCve={handleInspectCve} />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'news' && (
          <NewsRoomTab
            newsItems={newsFeed}
            stats={newsStats}
            loading={loadingNews}
            onRefresh={loadData}
            onInspectCve={handleInspectCve}
          />
        )}

        {activeTab === 'encyclopedia' && (
          <EncyclopediaTab initialQuery={encyclopediaQuery} />
        )}

        {activeTab === 'audit' && <AssetScannerTab />}

        {activeTab === 'hunter' && <ThreatHunterTab />}

        {activeTab === 'alerts' && <AlertsTab />}
      </main>

      {/* Cyber Ops Footer */}
      <footer className="border-t border-slate-800/80 bg-[#040711] py-6 text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-slate-300 font-bold">THREAT RADAR // CTI RADAR</span>
            <span>•</span>
            <span>Enterprise Cyber Threat Intelligence & Vulnerability Platform</span>
          </div>

          <div className="flex items-center gap-3 flex-wrap text-[11px]">
            <span className="text-slate-400">Feeds:</span>
            <span className="text-rose-400">CISA KEV</span>
            <span>•</span>
            <span className="text-cyan-400">GHSA</span>
            <span>•</span>
            <span className="text-indigo-400">NIST NVD</span>
            <span>•</span>
            <span className="text-amber-400">FIRST EPSS</span>
            <span>•</span>
            <span className="text-emerald-400">Feodo Tracker C2</span>
            <span>•</span>
            <span className="text-purple-400">URLhaus</span>
          </div>

          <div className="text-[11px] text-slate-500">
            Containerized • Agentless • Teams & Email Webhooks
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
