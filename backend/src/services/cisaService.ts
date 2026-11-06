import axios from 'axios';
import { CisaCatalogResponse, CisaKevItem } from '../types.js';

class CisaService {
  private cveMap: Map<string, CisaKevItem> = new Map();
  private vulnerabilities: CisaKevItem[] = [];
  private lastSyncTime: Date | null = null;
  private isSyncing = false;
  private syncIntervalMs = 6 * 60 * 60 * 1000; // 6 hours

  constructor() {
    // Start background sync on construct
  }

  public async initialize(): Promise<void> {
    console.log('[CISA KEV] Initializing CISA Known Exploited Vulnerabilities catalog...');
    await this.fetchCatalog();

    // Setup periodic 6-hour sync
    setInterval(() => {
      console.log('[CISA KEV] Triggering 6-hour scheduled sync...');
      this.fetchCatalog().catch((err) => {
        console.error('[CISA KEV] Scheduled sync failed:', err.message);
      });
    }, this.syncIntervalMs);
  }

  public async fetchCatalog(): Promise<boolean> {
    if (this.isSyncing) return false;
    this.isSyncing = true;

    try {
      const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
      console.log(`[CISA KEV] Fetching live feed from ${url}...`);

      const response = await axios.get<CisaCatalogResponse>(url, {
        timeout: 20000,
        headers: {
          'User-Agent': 'ThreatRadar/1.0 (Cyber Threat Intelligence Platform)',
          'Accept': 'application/json',
        },
      });

      if (response.data && Array.isArray(response.data.vulnerabilities)) {
        this.vulnerabilities = response.data.vulnerabilities;
        this.cveMap.clear();

        for (const item of this.vulnerabilities) {
          const normId = item.cveID.toUpperCase().trim();
          this.cveMap.set(normId, item);
        }

        this.lastSyncTime = new Date();
        console.log(`[CISA KEV] Successfully loaded ${this.vulnerabilities.length} active zero-days/exploited vulnerabilities. (Version: ${response.data.catalogVersion})`);
        return true;
      }
      return false;
    } catch (error: any) {
      console.warn(`[CISA KEV] Warning: Failed to fetch live CISA feed (${error.message}). Checking cached or fallback data...`);
      if (this.vulnerabilities.length === 0) {
        this.loadFallbackCatalog();
      }
      return false;
    } finally {
      this.isSyncing = false;
    }
  }

  private loadFallbackCatalog(): void {
    // Seed high-priority baseline KEV items in case initial HTTP fetch is interrupted
    const fallbackItems: CisaKevItem[] = [
      {
        cveID: 'CVE-2024-6387',
        vendorProject: 'OpenSSH',
        product: 'OpenSSH Server (regreSSHion)',
        vulnerabilityName: 'OpenSSH Server Remote Code Execution Vulnerability (regreSSHion)',
        dateAdded: '2024-07-08',
        shortDescription: 'A signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems.',
        requiredAction: 'Apply vendor updates immediately or mitigate by setting LoginGraceTime to 0 in sshd_config.',
        dueDate: '2024-07-29',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-362']
      },
      {
        cveID: 'CVE-2024-21413',
        vendorProject: 'Microsoft',
        product: 'Outlook',
        vulnerabilityName: 'Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)',
        dateAdded: '2024-03-05',
        shortDescription: 'Microsoft Outlook contains a remote code execution vulnerability bypassing Protected View when processing file:// links.',
        requiredAction: 'Apply vendor patches per Microsoft Advisory.',
        dueDate: '2024-03-26',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-94']
      },
      {
        cveID: 'CVE-2024-3400',
        vendorProject: 'Palo Alto Networks',
        product: 'PAN-OS',
        vulnerabilityName: 'Palo Alto Networks PAN-OS Command Injection Vulnerability',
        dateAdded: '2024-04-12',
        shortDescription: 'Command injection vulnerability in the GlobalProtect feature of PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges.',
        requiredAction: 'Apply updates per Palo Alto Networks Security Advisory.',
        dueDate: '2024-04-19',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-77']
      },
      {
        cveID: 'CVE-2024-21762',
        vendorProject: 'Fortinet',
        product: 'FortiOS',
        vulnerabilityName: 'Fortinet FortiOS Out-of-Bounds Write Vulnerability',
        dateAdded: '2024-02-09',
        shortDescription: 'An out-of-bounds write in Fortinet FortiOS may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.',
        requiredAction: 'Apply vendor updates immediately.',
        dueDate: '2024-02-16',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-787']
      },
      {
        cveID: 'CVE-2024-4577',
        vendorProject: 'PHP Group',
        product: 'PHP',
        vulnerabilityName: 'PHP CGI Argument Injection Vulnerability',
        dateAdded: '2024-06-12',
        shortDescription: 'PHP contains an argument injection vulnerability on Windows systems when running in CGI mode (Best-Fit character mapping bypass), allowing remote code execution.',
        requiredAction: 'Apply vendor updates per PHP Advisory.',
        dueDate: '2024-07-03',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-78']
      },
      {
        cveID: 'CVE-2024-38112',
        vendorProject: 'Microsoft',
        product: 'MSHTML Platform',
        vulnerabilityName: 'Microsoft MSHTML Platform Spoofing Vulnerability',
        dateAdded: '2024-07-09',
        shortDescription: 'Microsoft MSHTML platform contains a spoofing vulnerability that threat actors exploited via specially crafted .url shortcut files to force legacy Internet Explorer execution.',
        requiredAction: 'Apply July 2024 Windows Security Updates.',
        dueDate: '2024-07-30',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-451']
      },
      {
        cveID: 'CVE-2024-43451',
        vendorProject: 'Microsoft',
        product: 'Windows',
        vulnerabilityName: 'Microsoft Windows NTLM Hash Disclosure Spoofing Vulnerability',
        dateAdded: '2024-11-12',
        shortDescription: 'Microsoft Windows contains a spoofing vulnerability that exposes NTLMv2 hashes to remote attackers upon minimal user interaction with crafted files.',
        requiredAction: 'Apply Microsoft November 2024 Security Updates.',
        dueDate: '2024-12-03',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-200']
      },
      {
        cveID: 'CVE-2024-55591',
        vendorProject: 'Fortinet',
        product: 'FortiOS & FortiProxy',
        vulnerabilityName: 'Fortinet FortiOS and FortiProxy Authentication Bypass Vulnerability',
        dateAdded: '2025-01-14',
        shortDescription: 'An authentication bypass vulnerability in FortiOS and FortiProxy allows an unauthenticated attacker to gain administrator privileges via crafted requests to Node.js WebSocket.',
        requiredAction: 'Upgrade to patched firmware release.',
        dueDate: '2025-02-04',
        knownRansomwareCampaignUse: 'Known',
        cwes: ['CWE-287']
      }
    ];

    this.vulnerabilities = fallbackItems;
    this.cveMap.clear();
    for (const item of fallbackItems) {
      this.cveMap.set(item.cveID.toUpperCase(), item);
    }
    this.lastSyncTime = new Date();
    console.log(`[CISA KEV] Loaded ${this.vulnerabilities.length} baseline exploited vulnerabilities in fallback cache.`);
  }

  public isKnownExploited(cveId: string): boolean {
    if (!cveId) return false;
    return this.cveMap.has(cveId.toUpperCase().trim());
  }

  public getByCve(cveId: string): CisaKevItem | undefined {
    if (!cveId) return undefined;
    return this.cveMap.get(cveId.toUpperCase().trim());
  }

  public getAll(): CisaKevItem[] {
    return this.vulnerabilities;
  }

  public getRecent(limit = 15): CisaKevItem[] {
    // Sort descending by dateAdded
    return [...this.vulnerabilities]
      .sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())
      .slice(0, limit);
  }

  public search(query: string, limit = 50): CisaKevItem[] {
    if (!query || !query.trim()) return this.getRecent(limit);
    const q = query.toLowerCase().trim();

    return this.vulnerabilities
      .filter((item) => {
        return (
          item.cveID.toLowerCase().includes(q) ||
          item.product.toLowerCase().includes(q) ||
          item.vendorProject.toLowerCase().includes(q) ||
          item.vulnerabilityName.toLowerCase().includes(q) ||
          item.shortDescription.toLowerCase().includes(q)
        );
      })
      .sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())
      .slice(0, limit);
  }

  public getStatus() {
    return {
      totalKevCount: this.vulnerabilities.length,
      lastSyncTime: this.lastSyncTime ? this.lastSyncTime.toISOString() : null,
      isSyncing: this.isSyncing,
      status: this.vulnerabilities.length > 0 ? 'HEALTHY' : 'INITIALIZING',
    };
  }
}

export const cisaService = new CisaService();
