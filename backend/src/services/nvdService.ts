import axios from 'axios';
import { NvdApiResponse, NvdCveItem, NormalizedCve } from '../types.js';
import { cisaService } from './cisaService.js';
import { CURATED_CVE_DATABASE } from './sampleData.js';

interface CacheEntry {
  data: NormalizedCve[];
  timestamp: number;
}

class NvdService {
  private cache: Map<string, CacheEntry> = new Map();
  private cacheTtlMs = 15 * 60 * 1000; // 15 mins cache
  private baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  /**
   * Search CVEs by keyword or exact CVE ID using Smart Tail Fetching.
   */
  public async searchCves(query: string, limit = 20): Promise<NormalizedCve[]> {
    const cleanQuery = (query || '').trim();
    if (!cleanQuery) {
      return this.getRecentTrendingCves(limit);
    }

    const cacheKey = `search:${cleanQuery.toLowerCase()}:${limit}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
      return cached.data;
    }

    const isDirectCve = /^CVE-\d{4}-\d{4,}$/i.test(cleanQuery);

    try {
      let results: NormalizedCve[] = [];

      if (isDirectCve) {
        results = await this.fetchByCveId(cleanQuery.toUpperCase());
      } else {
        results = await this.smartTailSearch(cleanQuery, limit);
      }

      // If NIST didn't return any or returned few, supplement/fallback with local curated database & CISA
      if (results.length === 0) {
        results = this.searchCuratedAndCisa(cleanQuery, limit);
      }

      // Sort strictly descending by publication date
      results.sort((a, b) => new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime());

      this.cache.set(cacheKey, { data: results, timestamp: Date.now() });
      return results;
    } catch (error: any) {
      console.warn(`[NVD API] Search error for query "${query}": ${error.message}. Using fallback match.`);
      const fallbackResults = this.searchCuratedAndCisa(cleanQuery, limit);
      this.cache.set(cacheKey, { data: fallbackResults, timestamp: Date.now() });
      return fallbackResults;
    }
  }

  /**
   * Direct CVE lookup
   */
  private async fetchByCveId(cveId: string): Promise<NormalizedCve[]> {
    console.log(`[NVD API] Fetching specific CVE: ${cveId}`);
    const response = await axios.get<NvdApiResponse>(`${this.baseUrl}?cveId=${encodeURIComponent(cveId)}`, {
      timeout: 10000,
      headers: {
        'User-Agent': 'ThreatRadar/1.0 (Cyber Threat Intelligence Platform)',
        'Accept': 'application/json',
      },
    });

    if (response.data && response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
      return response.data.vulnerabilities.map((v) => this.normalizeNvdItem(v));
    }

    return [];
  }

  /**
   * Smart Tail Fetching Algorithm:
   * 1. Query totalResults with resultsPerPage=1
   * 2. Calculate startIndex = Math.max(0, totalResults - limit) to get the most recent CVEs
   * 3. Fetch tail chunk
   * 4. Reverse / sort descending by publication date
   */
  private async smartTailSearch(keyword: string, limit = 20): Promise<NormalizedCve[]> {
    console.log(`[NVD API] Initiating Smart Tail Search for: "${keyword}" (limit: ${limit})`);

    // Step 1: Probe count
    const countUrl = `${this.baseUrl}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=1`;
    const countResp = await axios.get<NvdApiResponse>(countUrl, {
      timeout: 8000,
      headers: {
        'User-Agent': 'ThreatRadar/1.0 (Cyber Threat Intelligence Platform)',
        'Accept': 'application/json',
      },
    });

    const totalResults = countResp.data?.totalResults || 0;
    console.log(`[NVD API] Total results found for "${keyword}": ${totalResults}`);

    if (totalResults === 0) {
      return [];
    }

    // Step 2: Calculate startIndex for the latest CVEs
    const startIndex = Math.max(0, totalResults - limit);
    const fetchLimit = Math.min(limit, totalResults);

    console.log(`[NVD API] Smart Tail Fetching: startIndex=${startIndex}, resultsPerPage=${fetchLimit}`);

    // Step 3: Fetch tail results
    const tailUrl = `${this.baseUrl}?keywordSearch=${encodeURIComponent(keyword)}&startIndex=${startIndex}&resultsPerPage=${fetchLimit}`;
    const tailResp = await axios.get<NvdApiResponse>(tailUrl, {
      timeout: 12000,
      headers: {
        'User-Agent': 'ThreatRadar/1.0 (Cyber Threat Intelligence Platform)',
        'Accept': 'application/json',
      },
    });

    if (tailResp.data && tailResp.data.vulnerabilities) {
      const normalized = tailResp.data.vulnerabilities.map((v) => this.normalizeNvdItem(v));
      return normalized;
    }

    return [];
  }

  /**
   * Normalize an NVD CVE Item into standard platform model with CISA KEV enrichment
   */
  private normalizeNvdItem(nvdItem: NvdCveItem): NormalizedCve {
    const cve = nvdItem.cve;
    const cveId = cve.id;

    // Extract English description
    const engDesc =
      cve.descriptions?.find((d) => d.lang === 'en')?.value ||
      cve.descriptions?.[0]?.value ||
      'No description provided by NIST NVD.';

    // Extract CVSS v3.1 / v3.0 / v2.0
    let cvssScore: number | null = null;
    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' = 'UNKNOWN';
    let attackVector: string | undefined = undefined;

    const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssV2 = cve.metrics?.cvssMetricV2?.[0];

    if (cvssV31) {
      cvssScore = cvssV31.baseScore;
      severity = (cvssV31.baseSeverity || 'UNKNOWN').toUpperCase() as any;
      attackVector = cvssV31.attackVector;
    } else if (cvssV30) {
      cvssScore = cvssV30.baseScore;
      severity = (cvssV30.baseSeverity || 'UNKNOWN').toUpperCase() as any;
      attackVector = cvssV30.attackVector;
    } else if (cvssV2) {
      cvssScore = cvssV2.cvssData?.baseScore || null;
      const sev = cvssV2.baseSeverity || '';
      severity = sev === 'HIGH' ? 'HIGH' : sev === 'MEDIUM' ? 'MEDIUM' : sev === 'LOW' ? 'LOW' : 'UNKNOWN';
    }

    // Cross-reference with CISA KEV
    const isKev = cisaService.isKnownExploited(cveId);
    const kevDetail = cisaService.getByCve(cveId);

    // Extract vendor and product heuristics
    let vendor = kevDetail?.vendorProject || 'Software Vendor';
    let product = kevDetail?.product || 'System Component';

    if (!kevDetail) {
      const words = engDesc.split(' ');
      if (words.length > 2) {
        vendor = words[0].replace(/[^a-zA-Z0-9]/g, '');
        product = words[1].replace(/[^a-zA-Z0-9]/g, '');
      }
    }

    const references = (cve.references || []).map((r) => r.url).slice(0, 5);

    const requiredAction = kevDetail
      ? kevDetail.requiredAction
      : severity === 'CRITICAL' || severity === 'HIGH'
      ? 'Apply latest security patches from vendor immediately.'
      : 'Review vendor guidance and schedule patching.';

    return {
      cveId,
      title: kevDetail?.vulnerabilityName || `${vendor} ${product} Vulnerability`,
      description: engDesc,
      vendor,
      product,
      cvssScore,
      severity,
      publishedDate: cve.published,
      lastModifiedDate: cve.lastModified,
      isZeroDay: isKev,
      isCisaKev: isKev,
      isRansomware: kevDetail?.knownRansomwareCampaignUse === 'Known',
      ransomwareCampaign: kevDetail?.knownRansomwareCampaignUse === 'Known' ? 'Known Ransomware Campaign' : undefined,
      requiredAction,
      dueDate: kevDetail?.dueDate,
      attackVector: attackVector || 'Remote Network',
      references,
      remediation: requiredAction,
    };
  }

  /**
   * Search CISA catalog and curated entries as high-speed lookup and fallback
   */
  public searchCuratedAndCisa(query: string, limit = 20): NormalizedCve[] {
    const q = query.toLowerCase().trim();
    const matches: NormalizedCve[] = [];
    const seen = new Set<string>();

    // 1. Curated database
    for (const item of CURATED_CVE_DATABASE) {
      if (
        item.cveId.toLowerCase().includes(q) ||
        item.title.toLowerCase().includes(q) ||
        item.product.toLowerCase().includes(q) ||
        item.vendor.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q)
      ) {
        if (!seen.has(item.cveId)) {
          seen.add(item.cveId);
          matches.push(item);
        }
      }
    }

    // 2. CISA KEV Catalog search
    const cisaItems = cisaService.search(query, limit);
    for (const cisaItem of cisaItems) {
      if (!seen.has(cisaItem.cveID)) {
        seen.add(cisaItem.cveID);
        matches.push({
          cveId: cisaItem.cveID,
          title: cisaItem.vulnerabilityName,
          description: cisaItem.shortDescription,
          vendor: cisaItem.vendorProject,
          product: cisaItem.product,
          cvssScore: 9.8, // KEV entries are high/critical zero days
          severity: 'CRITICAL',
          publishedDate: `${cisaItem.dateAdded}T00:00:00.000Z`,
          lastModifiedDate: `${cisaItem.dueDate}T00:00:00.000Z`,
          isZeroDay: true,
          isCisaKev: true,
          isRansomware: cisaItem.knownRansomwareCampaignUse === 'Known',
          ransomwareCampaign: cisaItem.knownRansomwareCampaignUse === 'Known' ? 'Active Campaign' : undefined,
          requiredAction: cisaItem.requiredAction,
          dueDate: cisaItem.dueDate,
          attackVector: 'Network / Exploitation in the Wild',
          references: [`https://nvd.nist.gov/vuln/detail/${cisaItem.cveID}`],
          remediation: cisaItem.requiredAction,
        });
      }
    }

    return matches.slice(0, limit);
  }

  /**
   * Get trending / recent high impact CVEs for default encyclopedia view
   */
  public getRecentTrendingCves(limit = 20): NormalizedCve[] {
    const cisaRecent = cisaService.getRecent(12);
    const results: NormalizedCve[] = [];
    const seen = new Set<string>();

    for (const item of CURATED_CVE_DATABASE) {
      if (!seen.has(item.cveId)) {
        seen.add(item.cveId);
        results.push(item);
      }
    }

    for (const k of cisaRecent) {
      if (!seen.has(k.cveID)) {
        seen.add(k.cveID);
        results.push({
          cveId: k.cveID,
          title: k.vulnerabilityName,
          description: k.shortDescription,
          vendor: k.vendorProject,
          product: k.product,
          cvssScore: 9.8,
          severity: 'CRITICAL',
          publishedDate: `${k.dateAdded}T00:00:00.000Z`,
          lastModifiedDate: `${k.dueDate}T00:00:00.000Z`,
          isZeroDay: true,
          isCisaKev: true,
          isRansomware: k.knownRansomwareCampaignUse === 'Known',
          ransomwareCampaign: k.knownRansomwareCampaignUse === 'Known' ? 'Known Ransomware Campaign' : undefined,
          requiredAction: k.requiredAction,
          dueDate: k.dueDate,
          attackVector: 'Network',
          references: [`https://nvd.nist.gov/vuln/detail/${k.cveID}`],
          remediation: k.requiredAction,
        });
      }
    }

    return results
      .sort((a, b) => new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime())
      .slice(0, limit);
  }
}

export const nvdService = new NvdService();
