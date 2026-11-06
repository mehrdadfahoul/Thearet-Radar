import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  UploadCloud,
  Globe,
  Radio,
  FileCode,
  Link as LinkIcon,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Terminal,
  Database,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import { threatApi } from '../services/api';
import { IpCheckResult, BulkIpScanResult, FileScanResult, UrlScanResult } from '../types';

export const ThreatHunterTab: React.FC = () => {
  const [subTab, setSubTab] = useState<'ip' | 'scanner'>('ip');

  // IP Radar State
  const [singleIp, setSingleIp] = useState('');
  const [ipLoading, setIpLoading] = useState(false);
  const [singleResult, setSingleResult] = useState<IpCheckResult | null>(null);
  const [logContent, setLogContent] = useState('');
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResult, setBulkResult] = useState<BulkIpScanResult | null>(null);
  const [feedStatus, setFeedStatus] = useState<any>(null);

  // File & URL Scanner State
  const [fileLoading, setFileLoading] = useState(false);
  const [fileResult, setFileResult] = useState<FileScanResult | null>(null);
  const [urlInput, setUrlInput] = useState('');
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlResult, setUrlResult] = useState<UrlScanResult | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    threatApi.getIpFeedStatus().then(setFeedStatus).catch(() => null);
  }, []);

  const handleCheckSingleIp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!singleIp.trim()) return;
    setIpLoading(true);
    setSingleResult(null);
    try {
      const res = await threatApi.checkIp(singleIp.trim());
      setSingleResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIpLoading(false);
    }
  };

  const handleBulkScan = async () => {
    if (!logContent.trim()) return;
    setBulkLoading(true);
    try {
      const res = await threatApi.bulkScanLogs(logContent);
      setBulkResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setBulkLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setFileLoading(true);
    setFileResult(null);
    try {
      const res = await threatApi.scanFile(file);
      setFileResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setFileLoading(false);
    }
  };

  const handleUrlScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setUrlLoading(true);
    setUrlResult(null);
    try {
      const res = await threatApi.scanUrl(urlInput.trim());
      setUrlResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setUrlLoading(false);
    }
  };

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(type);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Sub-navigation */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setSubTab('ip')}
            className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider flex items-center gap-2 transition-all ${
              subTab === 'ip'
                ? 'bg-rose-950 text-rose-300 border border-rose-700 shadow-md shadow-rose-950'
                : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
            }`}
          >
            <Radio className="w-4 h-4 text-rose-500" />
            <span>MALICIOUS IP & C2 RADAR</span>
          </button>

          <button
            onClick={() => setSubTab('scanner')}
            className={`px-4 py-2 rounded-lg text-xs font-mono font-bold tracking-wider flex items-center gap-2 transition-all ${
              subTab === 'scanner'
                ? 'bg-indigo-950 text-indigo-300 border border-indigo-700 shadow-md shadow-indigo-950'
                : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-indigo-400" />
            <span>VIRUSTOTAL-STYLE FILE & URL SCANNER</span>
          </button>
        </div>

        {feedStatus && (
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Tracked C2 Infrastructure:</span>
            <span className="text-emerald-400 font-bold">{feedStatus.totalMaliciousIps.toLocaleString()} IPs</span>
          </div>
        )}
      </div>

      {/* ================= TAB 1: MALICIOUS IP RADAR ================= */}
      {subTab === 'ip' && (
        <div className="space-y-6">
          {/* Top Single IP Check Box */}
          <div className="cyber-card p-6 border-rose-900/40 bg-gradient-to-br from-[#150711]/95 to-[#0b0f19]/95 relative overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-md bg-rose-950 border border-rose-700 text-rose-400">
                <Globe className="w-4 h-4" />
              </span>
              <h3 className="text-base font-bold font-mono tracking-wide text-white">
                GLOBAL MALICIOUS IP REPUTATION CHECK
              </h3>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl font-sans mb-4">
              Query any IPv4 address against active command-and-control (C2) botnets, brute-force nodes, and ransomware exfiltration servers worldwide (Abuse.ch Feodo Tracker, Blocklist.de, AlienVault OTX).
            </p>

            <form onSubmit={handleCheckSingleIp} className="flex items-center gap-2 max-w-xl">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-rose-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={singleIp}
                  onChange={(e) => setSingleIp(e.target.value)}
                  placeholder="e.g. 194.26.29.112 or 45.148.10.155"
                  className="w-full pl-10 pr-4 py-2.5 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-rose-500"
                />
              </div>

              <button
                type="submit"
                disabled={ipLoading}
                className="px-5 py-2.5 bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 text-white rounded-lg text-xs font-mono font-bold tracking-wider flex items-center gap-1.5 shadow-md shadow-rose-950 transition-all disabled:opacity-50"
              >
                {ipLoading ? 'QUERYING...' : 'CHECK IP'}
              </button>
            </form>

            {/* Quick Demo IP Pills */}
            <div className="mt-3 flex items-center gap-2 flex-wrap text-xs font-mono text-slate-400">
              <span>Quick Test Targets:</span>
              <button
                type="button"
                onClick={() => {
                  setSingleIp('194.26.29.112');
                  threatApi.checkIp('194.26.29.112').then(setSingleResult);
                }}
                className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-rose-400 hover:bg-slate-800"
              >
                194.26.29.112 (QakBot C2)
              </button>
              <button
                type="button"
                onClick={() => {
                  setSingleIp('45.148.10.155');
                  threatApi.checkIp('45.148.10.155').then(setSingleResult);
                }}
                className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-amber-400 hover:bg-slate-800"
              >
                45.148.10.155 (LockBit 3.0 Node)
              </button>
              <button
                type="button"
                onClick={() => {
                  setSingleIp('8.8.8.8');
                  threatApi.checkIp('8.8.8.8').then(setSingleResult);
                }}
                className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-emerald-400 hover:bg-slate-800"
              >
                8.8.8.8 (Clean DNS)
              </button>
            </div>

            {/* Single Result Box */}
            {singleResult && (
              <div
                className={`mt-4 p-4 rounded-xl border text-xs font-mono animate-in fade-in duration-200 ${
                  singleResult.isMalicious
                    ? 'bg-rose-950/30 border-rose-700/80 text-rose-200'
                    : 'bg-emerald-950/30 border-emerald-700/80 text-emerald-200'
                }`}
              >
                <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-extrabold text-sm text-white px-2 py-0.5 bg-slate-900 rounded border border-slate-700">
                      {singleResult.ip}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        singleResult.isMalicious ? 'bg-rose-600 text-white animate-pulse' : 'bg-emerald-600 text-white'
                      }`}
                    >
                      {singleResult.verdict}
                    </span>
                  </div>

                  <span className="text-slate-300 font-bold">
                    Risk Score: {singleResult.riskScore} / 100
                  </span>
                </div>

                {singleResult.details && (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 my-2 text-[11px] bg-slate-950/60 p-2.5 rounded border border-slate-800">
                    <div>
                      <span className="text-slate-500 block uppercase">Threat Category</span>
                      <strong className="text-rose-400">{singleResult.details.threatType}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500 block uppercase">Malware Family</span>
                      <strong className="text-white">{singleResult.details.malwareFamily}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500 block uppercase">Feed Source</span>
                      <strong className="text-slate-300">{singleResult.details.source}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500 block uppercase">Country</span>
                      <strong className="text-slate-300">{singleResult.details.country || 'Global'}</strong>
                    </div>
                  </div>
                )}

                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 mt-2 text-[11px] leading-relaxed">
                  <strong className="text-slate-400 block mb-0.5">Recommended SecOps Action:</strong>
                  <span>{singleResult.recommendation}</span>
                </div>
              </div>
            )}
          </div>

          {/* Bulk Server Log / Firewall Scanner */}
          <div className="cyber-card p-6 border-slate-800">
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-md bg-slate-900 border border-slate-700 text-slate-300">
                <Terminal className="w-4 h-4 text-cyan-400" />
              </span>
              <h3 className="text-base font-bold font-mono tracking-wide text-white">
                BULK LOG & FIREWALL TRAFFIC CORRELATOR
              </h3>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl font-sans mb-3">
              Paste raw Nginx/Apache access logs, SSH auth logs, or firewall connection dumps. The engine extracts all IPv4 addresses and correlates them against global botnet C2s.
            </p>

            <textarea
              rows={4}
              value={logContent}
              onChange={(e) => setLogContent(e.target.value)}
              placeholder="Paste logs here (e.g. Nov 6 12:44:01 srv sshd[1299]: Failed password for root from 194.26.29.112 port 4492 ssh2...)"
              className="w-full p-3 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />

            <div className="mt-3 flex items-center justify-between flex-wrap gap-2">
              <button
                type="button"
                onClick={() => {
                  setLogContent(`Nov 06 14:22:01 edge-fw01 kernel: [DROPPED] SRC=194.26.29.112 DST=10.0.0.4 PROTO=TCP DPT=443
Nov 06 14:22:15 edge-fw01 sshd[9182]: Failed password from 185.196.8.246 port 51222 ssh2
Nov 06 14:23:40 auth-server nginx: 45.148.10.155 - - [06/Nov/2026:14:23:40] "POST /api/v1/auth" 401 128
Nov 06 14:24:00 internal-dns: Query from 192.168.1.45 for google.com`);
                }}
                className="text-xs font-mono text-cyan-400 hover:underline"
              >
                + Insert Sample Firewall Log
              </button>

              <button
                onClick={handleBulkScan}
                disabled={bulkLoading || !logContent.trim()}
                className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-700 hover:from-cyan-500 text-white text-xs font-mono font-bold tracking-wider shadow-md shadow-cyan-950 transition-all disabled:opacity-50"
              >
                {bulkLoading ? 'ANALYZING TRAFFIC...' : 'CORRELATE LOGS'}
              </button>
            </div>

            {/* Bulk Results Table */}
            {bulkResult && (
              <div className="mt-5 space-y-4 animate-in fade-in duration-200">
                <div className="grid grid-cols-3 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block uppercase">Total IPs Found</span>
                    <strong className="text-lg text-white">{bulkResult.totalAnalyzed}</strong>
                  </div>
                  <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800">
                    <span className="text-rose-400 block uppercase font-bold">Malicious C2 Detections</span>
                    <strong className="text-lg text-rose-300">{bulkResult.maliciousFound}</strong>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800">
                    <span className="text-emerald-400 block uppercase font-bold">Clean Connections</span>
                    <strong className="text-lg text-emerald-300">{bulkResult.cleanFound}</strong>
                  </div>
                </div>

                {bulkResult.detections.length > 0 && (
                  <div className="overflow-x-auto rounded-lg border border-slate-800">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-900 text-slate-400 text-[11px] uppercase border-b border-slate-800">
                        <tr>
                          <th className="p-3">Infected / Malicious IP</th>
                          <th className="p-3">Threat Type</th>
                          <th className="p-3">Malware Family</th>
                          <th className="p-3">Source</th>
                          <th className="p-3 text-right">Risk Score</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {bulkResult.detections.map((d, idx) => (
                          <tr key={idx} className="bg-rose-950/20 hover:bg-rose-950/40">
                            <td className="p-3 font-bold text-rose-300">{d.ip}</td>
                            <td className="p-3 text-slate-300">{d.details?.threatType}</td>
                            <td className="p-3 text-white font-semibold">{d.details?.malwareFamily}</td>
                            <td className="p-3 text-slate-400 text-[11px]">{d.details?.source}</td>
                            <td className="p-3 text-right font-bold text-rose-400">{d.riskScore}%</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ================= TAB 2: VIRUSTOTAL STYLE SCANNER ================= */}
      {subTab === 'scanner' && (
        <div className="space-y-6">
          {/* File Upload Zone */}
          <div className="cyber-card p-6 border-indigo-900/40 bg-gradient-to-br from-[#0c0d1c]/95 to-[#0b0f19]/95 relative overflow-hidden">
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-md bg-indigo-950 border border-indigo-700 text-indigo-400">
                <FileCode className="w-4 h-4" />
              </span>
              <h3 className="text-base font-bold font-mono tracking-wide text-white">
                VIRUSTOTAL-STYLE FILE HASH & SIGNATURE SCANNER
              </h3>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl font-sans mb-4">
              Upload any suspicious executable, binary, or script (up to 30MB). ThreatRadar automatically computes MD5, SHA-1, and SHA-256 cryptographic hashes and inspects global malware repositories (Abuse.ch MalwareBazaar & Curated Signatures).
            </p>

            <div
              onClick={() => document.getElementById('suspicious-file-input')?.click()}
              className="border-2 border-dashed border-indigo-700/60 hover:border-indigo-500 rounded-xl p-8 text-center cursor-pointer bg-slate-950/40 hover:bg-slate-900/40 transition-colors"
            >
              <input
                id="suspicious-file-input"
                type="file"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
              />
              <UploadCloud className="w-10 h-10 text-indigo-400 mx-auto mb-2 animate-pulse" />
              <p className="text-xs font-mono font-bold text-slate-200">
                Drop suspicious file here or <span className="text-indigo-400 underline">browse disk</span>
              </p>
              <p className="text-[11px] text-slate-500 font-mono mt-1">
                Zero file storage on disk • Pure in-memory cryptographic hash verification
              </p>
            </div>

            {fileLoading && (
              <div className="mt-4 p-4 text-center font-mono text-xs text-indigo-300">
                Calculating MD5, SHA-1, SHA-256 and querying global signature databases...
              </div>
            )}

            {/* File Scan Result */}
            {fileResult && (
              <div
                className={`mt-4 p-5 rounded-xl border text-xs font-mono animate-in fade-in duration-200 ${
                  fileResult.isMalicious
                    ? 'bg-rose-950/30 border-rose-700/80 text-rose-200'
                    : fileResult.verdict === 'SUSPICIOUS'
                    ? 'bg-amber-950/30 border-amber-700/80 text-amber-200'
                    : 'bg-emerald-950/30 border-emerald-700/80 text-emerald-200'
                }`}
              >
                <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
                  <div>
                    <span className="text-slate-400 text-[10px] uppercase block">Scanned File</span>
                    <strong className="text-sm text-white">{fileResult.fileName}</strong>
                    <span className="text-slate-400 ml-2">({fileResult.fileSize} MB)</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`px-3 py-1 rounded text-xs font-bold uppercase ${
                        fileResult.isMalicious
                          ? 'bg-rose-600 text-white animate-pulse'
                          : fileResult.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-600 text-white'
                          : 'bg-emerald-600 text-white'
                      }`}
                    >
                      {fileResult.verdict}
                    </span>
                    <span className="px-2 py-1 bg-slate-900 rounded border border-slate-700 text-slate-300 text-[11px]">
                      {fileResult.detectionRatio}
                    </span>
                  </div>
                </div>

                {/* Hashes Row */}
                <div className="space-y-1.5 p-3 rounded bg-slate-950/70 border border-slate-800 text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">SHA-256:</span>
                    <span className="text-cyan-300 truncate max-w-md">{fileResult.sha256}</span>
                    <button
                      onClick={() => copyToClipboard(fileResult.sha256, 'sha256')}
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">MD5:</span>
                    <span className="text-slate-300 truncate max-w-md">{fileResult.md5}</span>
                    <button
                      onClick={() => copyToClipboard(fileResult.md5, 'md5')}
                      className="text-slate-400 hover:text-white"
                    >
                      {copiedHash === 'md5' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Threat Details */}
                {fileResult.threatName && (
                  <div className="mt-3 p-3 rounded bg-slate-900/80 border border-slate-800 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white block">{fileResult.threatName}</strong>
                      <span className="text-slate-300 text-[11px] leading-relaxed block mt-1">
                        {fileResult.analysisSummary}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* URL & Link Scanner */}
          <div className="cyber-card p-6 border-slate-800">
            <div className="flex items-center gap-2 mb-2">
              <span className="p-1.5 rounded-md bg-slate-900 border border-slate-700 text-slate-300">
                <LinkIcon className="w-4 h-4 text-indigo-400" />
              </span>
              <h3 className="text-base font-bold font-mono tracking-wide text-white">
                MALICIOUS URL & PHISHING LINK RADAR
              </h3>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl font-sans mb-3">
              Inspect suspicious URLs, domains, or download links against Abuse.ch URLhaus malware distribution feeds.
            </p>

            <form onSubmit={handleUrlScan} className="flex items-center gap-2 max-w-2xl">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="e.g. http://malicious-domain.top/payload.exe or suspicious domain"
                className="w-full px-4 py-2.5 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />

              <button
                type="submit"
                disabled={urlLoading}
                className="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 text-white rounded-lg text-xs font-mono font-bold tracking-wider shadow-md shadow-indigo-950 transition-all disabled:opacity-50 flex-shrink-0"
              >
                {urlLoading ? 'SCANNING...' : 'SCAN URL'}
              </button>
            </form>

            {urlResult && (
              <div
                className={`mt-4 p-4 rounded-xl border text-xs font-mono animate-in fade-in duration-200 ${
                  urlResult.isMalicious
                    ? 'bg-rose-950/30 border-rose-700/80 text-rose-200'
                    : urlResult.verdict === 'SUSPICIOUS'
                    ? 'bg-amber-950/30 border-amber-700/80 text-amber-200'
                    : 'bg-emerald-950/30 border-emerald-700/80 text-emerald-200'
                }`}
              >
                <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
                  <span className="font-bold text-white truncate max-w-md">{urlResult.url}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      urlResult.isMalicious
                        ? 'bg-rose-600 text-white animate-pulse'
                        : urlResult.verdict === 'SUSPICIOUS'
                        ? 'bg-amber-600 text-white'
                        : 'bg-emerald-600 text-white'
                    }`}
                  >
                    {urlResult.verdict}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                  <div>
                    <span className="text-slate-500">Threat Assessment:</span>{' '}
                    <strong className="text-white">{urlResult.threatType}</strong>
                  </div>
                  <div>
                    <span className="text-slate-500">Guidance:</span>{' '}
                    <span className="text-slate-300">{urlResult.recommendation}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
