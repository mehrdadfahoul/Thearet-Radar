import axios from 'axios';
import {
  UnifiedThreatNews,
  NewsStats,
  TickerItem,
  NormalizedCve,
  AuditSummary,
  HealthStatus,
  IpCheckResult,
  BulkIpScanResult,
  FileScanResult,
  UrlScanResult,
  AlertConfig,
} from '../types';

const API_BASE = '/api';

export const threatApi = {
  // News & Zero-Days
  async getNewsFeed(): Promise<{ stats: NewsStats; feed: UnifiedThreatNews[] }> {
    const res = await axios.get(`${API_BASE}/news`);
    return {
      stats: res.data.stats,
      feed: res.data.feed,
    };
  },

  async getTicker(): Promise<TickerItem[]> {
    const res = await axios.get(`${API_BASE}/news/ticker`);
    return res.data.ticker || [];
  },

  // CVE Encyclopedia & Search
  async searchCves(query: string, limit = 20): Promise<{ count: number; results: NormalizedCve[] }> {
    const res = await axios.get(`${API_BASE}/cve/search`, {
      params: { q: query, limit },
    });
    return {
      count: res.data.count,
      results: res.data.results,
    };
  },

  async getCveDetails(cveId: string): Promise<NormalizedCve> {
    const res = await axios.get(`${API_BASE}/cve/details/${encodeURIComponent(cveId)}`);
    return res.data.cve;
  },

  getSampleTemplateUrl(): string {
    return `${API_BASE}/cve/sample-template`;
  },

  // Asset Scanner / Audit (Excel, CSV, Nmap XML, Nessus)
  async uploadAndAuditFile(file: File): Promise<{ filename: string; format?: string; summary: AuditSummary }> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await axios.post(`${API_BASE}/audit/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },

  async loadDemoAudit(): Promise<{ filename: string; summary: AuditSummary }> {
    const res = await axios.get(`${API_BASE}/audit/demo`);
    return res.data;
  },

  // Malicious IP CTI & Log Scanner
  async checkIp(ip: string): Promise<IpCheckResult> {
    const res = await axios.get(`${API_BASE}/threat-intel/ip/check`, {
      params: { ip },
    });
    return res.data.result;
  },

  async bulkScanLogs(logs: string): Promise<BulkIpScanResult> {
    const res = await axios.post(`${API_BASE}/threat-intel/ip/bulk-scan`, { logs });
    return res.data.result;
  },

  async getIpFeedStatus(): Promise<any> {
    const res = await axios.get(`${API_BASE}/threat-intel/ip/status`);
    return res.data.feed;
  },

  // VirusTotal Style File & URL Scanner
  async scanFile(file: File): Promise<FileScanResult> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await axios.post(`${API_BASE}/threat-intel/scan-file`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data.result;
  },

  async scanUrl(url: string): Promise<UrlScanResult> {
    const res = await axios.post(`${API_BASE}/threat-intel/scan-url`, { url });
    return res.data.result;
  },

  // Alerts & Integrations (Teams & Email)
  async getAlertConfig(): Promise<AlertConfig> {
    const res = await axios.get(`${API_BASE}/alerts/config`);
    return res.data.config;
  },

  async updateAlertConfig(config: Partial<AlertConfig>): Promise<AlertConfig> {
    const res = await axios.post(`${API_BASE}/alerts/config`, config);
    return res.data.config;
  },

  async testTeamsAlert(webhookUrl?: string): Promise<{ success: boolean; message: string }> {
    const res = await axios.post(`${API_BASE}/alerts/test-teams`, { webhookUrl });
    return res.data;
  },

  async testEmailAlert(recipients?: string): Promise<{ success: boolean; message: string; simulated?: boolean }> {
    const res = await axios.post(`${API_BASE}/alerts/test-email`, { recipients });
    return res.data;
  },

  // Health
  async getHealth(): Promise<HealthStatus> {
    const res = await axios.get(`${API_BASE}/health`);
    return res.data;
  },
};
