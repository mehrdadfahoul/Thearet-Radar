export interface UnifiedThreatNews {
  id: string;
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

export interface NewsStats {
  totalThreats: number;
  totalCisaKev: number;
  lastSync: string | null;
  activeZeroDaysCount: number;
  ransomwareTargetsCount: number;
}

export interface TickerItem {
  cveId: string;
  title: string;
  vendor: string;
  product: string;
  dateAdded: string;
  isRansomware: boolean;
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

export interface HealthStatus {
  status: string;
  platform: string;
  timestamp: string;
  uptimeSeconds: number;
  feeds: {
    cisaKev: {
      status: string;
      count: number;
      lastSync: string | null;
      resyncIntervalHours: number;
    };
    githubAdvisories: {
      status: string;
      cacheDurationMinutes: number;
    };
    nvdApiV2: {
      status: string;
      mode: string;
    };
  };
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
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface IpCheckResult {
  ip: string;
  isMalicious: boolean;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN';
  details?: MaliciousIpItem;
  riskScore: number;
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
