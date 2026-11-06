export interface CisaKevItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string; // YYYY-MM-DD
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string; // "Known" | "Unknown"
  notes?: string;
  cwes?: string[];
}

export interface CisaCatalogResponse {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevItem[];
}

export interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: 'low' | 'moderate' | 'high' | 'critical';
  cvss: {
    vector_string: string | null;
    score: number | null;
  };
  published_at: string;
  updated_at: string;
  html_url: string;
  vulnerabilities?: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    vulnerable_version_range?: string;
    first_patched_version?: string;
  }>;
}

export interface EpssRecord {
  cve: string;
  epss: number; // 0.0 to 1.0 (e.g. 0.942 = 94.2% probability of exploitation in next 30 days)
  percentile: number; // 0.0 to 1.0 (e.g. 0.985 = 98.5th percentile)
  date?: string;
}

export interface UnifiedThreatNews {
  id: string; // CVE or GHSA
  cveId?: string;
  title: string;
  summary: string;
  vendor: string;
  product: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvssScore: number | null;
  epssScore?: number | null;
  epssPercentile?: number | null;
  publishedAt: string;
  humanizedDate: string;
  isZeroDay: boolean;
  isCisaKev: boolean;
  isRansomware: boolean;
  ransomwareCampaign?: string;
  requiredAction?: string;
  source: 'CISA KEV' | 'GitHub Advisory' | 'NVD';
  bulletinUrl: string;
  attackVector?: string;
}

export interface NvdCveItem {
  cve: {
    id: string;
    sourceIdentifier?: string;
    published: string;
    lastModified: string;
    vulnStatus?: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: {
          version: string;
          vectorString: string;
          baseScore: number;
          baseSeverity: string;
          attackVector?: string;
        };
      }>;
      cvssMetricV30?: Array<{
        cvssData: {
          version: string;
          vectorString: string;
          baseScore: number;
          baseSeverity: string;
          attackVector?: string;
        };
      }>;
      cvssMetricV2?: Array<{
        cvssData: {
          version: string;
          baseScore: number;
        };
        baseSeverity?: string;
      }>;
    };
    weaknesses?: Array<{
      description: Array<{ lang: string; value: string }>;
    }>;
    configurations?: any[];
    references?: Array<{
      url: string;
      source?: string;
      tags?: string[];
    }>;
  };
}

export interface NvdApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: NvdCveItem[];
}

export interface NormalizedCve {
  cveId: string;
  title: string;
  description: string;
  vendor: string;
  product: string;
  cvssScore: number | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  epssScore?: number | null;
  epssPercentile?: number | null;
  publishedDate: string;
  lastModifiedDate: string;
  isZeroDay: boolean;
  isCisaKev: boolean;
  isRansomware: boolean;
  ransomwareCampaign?: string;
  requiredAction?: string;
  dueDate?: string;
  attackVector?: string;
  references: string[];
  remediation?: string;
}

export interface AssetItem {
  softwareName: string;
  version?: string;
  category?: string;
  department?: string;
  host?: string;
  port?: number | string;
  source?: 'EXCEL' | 'CSV' | 'NMAP' | 'NESSUS';
  rawRow?: Record<string, any>;
}

export interface AssetAuditResult {
  asset: AssetItem;
  riskStatus: 'ACTIVE ZERO-DAY' | 'CRITICAL' | 'HIGH' | 'SAFE';
  highestCvss: number;
  highestEpss?: number;
  zeroDayCount: number;
  criticalCount: number;
  totalCveCount: number;
  matchedCves: NormalizedCve[];
}

export interface AuditSummary {
  totalAssets: number;
  activeZeroDays: number;
  criticalAssets: number;
  highRiskAssets: number;
  safeAssets: number;
  scannedAt: string;
  sourceFormat?: 'EXCEL_CSV' | 'NMAP_XML' | 'NESSUS_XML' | 'NESSUS_CSV';
  results: AssetAuditResult[];
}

// IP Reputation & CTI Types
export interface MaliciousIpItem {
  ip: string;
  threatType: 'C2_BOTNET' | 'BRUTE_FORCE' | 'RANSOMWARE' | 'SCANNER' | 'MALICIOUS_HOST';
  malwareFamily?: string;
  country?: string;
  asNumber?: string;
  asName?: string;
  firstSeen?: string;
  lastSeen?: string;
  source: string; // Feodo Tracker, Blocklist.de, Emerging Threats, AlienVault
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface IpCheckResult {
  ip: string;
  isMalicious: boolean;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN';
  details?: MaliciousIpItem;
  riskScore: number; // 0-100
  recommendation: string;
}

export interface BulkIpScanResult {
  totalAnalyzed: number;
  maliciousFound: number;
  cleanFound: number;
  detections: IpCheckResult[];
}

// Threat Hunter / VirusTotal Style Scanner Types
export interface FileScanResult {
  fileName: string;
  fileSize: number;
  fileSizeBytes: number;
  md5: string;
  sha1: string;
  sha256: string;
  isMalicious: boolean;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN';
  threatName?: string;
  malwareFamily?: string;
  detectionRatio?: string;
  firstSeen?: string;
  fileType?: string;
  tags?: string[];
  source?: string;
  details?: Record<string, any>;
  analysisSummary: string;
}

export interface UrlScanResult {
  url: string;
  domain: string;
  isMalicious: boolean;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN';
  threatType?: string;
  tags?: string[];
  reporter?: string;
  status?: string;
  firstSeen?: string;
  source?: string;
  details?: Record<string, any>;
  recommendation: string;
}

// Alert Integration Types
export interface AlertConfig {
  teamsWebhookUrl?: string;
  teamsEnabled: boolean;
  smtpHost?: string;
  smtpPort?: number;
  smtpUser?: string;
  smtpPass?: string;
  smtpFrom?: string;
  alertRecipients?: string;
  emailEnabled: boolean;
  notifyOnZeroDay: boolean;
  notifyOnCritical: boolean;
}
