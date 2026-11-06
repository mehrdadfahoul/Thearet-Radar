import * as xlsx from 'xlsx';
import { AssetItem, AssetAuditResult, AuditSummary, NormalizedCve } from '../types.js';
import { cisaService } from './cisaService.js';
import { nvdService } from './nvdService.js';
import { CURATED_CVE_DATABASE } from './sampleData.js';
import { scannerAuditService } from './scannerAuditService.js';
import { epssService } from './epssService.js';
import { alertService } from './alertService.js';

class AuditService {
  /**
   * Parse uploaded file: Excel (.xlsx, .xls), CSV (.csv), Nmap XML (.xml), or Nessus (.nessus)
   */
  public parseUploadedFile(fileBuffer: Buffer, fileName: string): { assets: AssetItem[]; format: 'EXCEL_CSV' | 'NMAP_XML' | 'NESSUS_XML' | 'NESSUS_CSV' } {
    const contentStr = fileBuffer.toString('utf-8', 0, Math.min(fileBuffer.length, 4096));

    // 1. Detect Nmap XML
    if (contentStr.includes('<nmaprun') || contentStr.includes('scanner="nmap"')) {
      const fullXml = fileBuffer.toString('utf-8');
      const assets = scannerAuditService.parseNmapXml(fullXml);
      return { assets, format: 'NMAP_XML' };
    }

    // 2. Detect Nessus XML (.nessus)
    if (contentStr.includes('<NessusClientData') || contentStr.includes('<ReportHost')) {
      const fullXml = fileBuffer.toString('utf-8');
      const { assets } = scannerAuditService.parseNessusXml(fullXml);
      return { assets, format: 'NESSUS_XML' };
    }

    // 3. Fallback to Excel (.xlsx, .xls) or CSV
    const workbook = xlsx.read(fileBuffer, { type: 'buffer', raw: true, cellDates: false, cellText: true });
    if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
      throw new Error('The uploaded file does not contain any readable sheets.');
    }

    const firstSheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[firstSheetName];
    const rawRows = xlsx.utils.sheet_to_json<Record<string, any>>(sheet, { raw: true, defval: '' });

    if (!rawRows || rawRows.length === 0) {
      throw new Error('The uploaded file is empty or does not have row data.');
    }

    // Check if it's a Nessus CSV
    const firstRowKeys = Object.keys(rawRows[0] || {}).map((k) => k.toLowerCase());
    if (firstRowKeys.includes('plugin id') && firstRowKeys.includes('cve')) {
      const { assets } = scannerAuditService.parseNessusCsv(rawRows);
      return { assets, format: 'NESSUS_CSV' };
    }

    return { assets: this.mapRowsToAssets(rawRows), format: 'EXCEL_CSV' };
  }

  /**
   * Smart column header detection (case-insensitive & fuzzy)
   */
  private mapRowsToAssets(rawRows: Record<string, any>[]): AssetItem[] {
    return rawRows.map((row) => {
      const keys = Object.keys(row);

      const findKey = (patterns: RegExp[]): string | undefined => {
        return keys.find((k) => patterns.some((p) => p.test(k.trim())));
      };

      const softwareKey = findKey([
        /^software\s*name$/i,
        /^software$/i,
        /^application\s*name$/i,
        /^application$/i,
        /^app$/i,
        /^product$/i,
        /^asset\s*name$/i,
        /^asset$/i,
        /^package$/i,
        /^name$/i,
      ]) || keys[0];

      const versionKey = findKey([
        /^version$/i,
        /^ver$/i,
        /^release$/i,
        /^build$/i,
        /^v$/i,
      ]);

      const categoryKey = findKey([
        /^category$/i,
        /^software\s*category$/i,
        /^type$/i,
        /^classification$/i,
        /^class$/i,
      ]);

      const departmentKey = findKey([
        /^department$/i,
        /^dept$/i,
        /^team$/i,
        /^owner$/i,
        /^business\s*unit$/i,
        /^division$/i,
      ]);

      const hostKey = findKey([
        /^host\s*\/?\s*workstation$/i,
        /^host$/i,
        /^hostname$/i,
        /^workstation$/i,
        /^server$/i,
        /^machine$/i,
        /^device$/i,
        /^ip(\s*address)?$/i,
        /^endpoint$/i,
      ]);

      const softwareName = row[softwareKey] ? String(row[softwareKey]).trim() : 'Unknown Software';
      const version = versionKey && row[versionKey] ? String(row[versionKey]).trim() : undefined;
      const category = categoryKey && row[categoryKey] ? String(row[categoryKey]).trim() : 'General Application';
      const department = departmentKey && row[departmentKey] ? String(row[departmentKey]).trim() : 'Enterprise IT';
      const host = hostKey && row[hostKey] ? String(row[hostKey]).trim() : 'Unassigned Host';

      return {
        softwareName,
        version,
        category,
        department,
        host,
        source: 'EXCEL',
        rawRow: row,
      };
    });
  }

  /**
   * Correlate software assets with live CISA KEV, NIST CVE feeds, and FIRST.org EPSS
   */
  public async auditAssets(assets: AssetItem[], format: 'EXCEL_CSV' | 'NMAP_XML' | 'NESSUS_XML' | 'NESSUS_CSV' = 'EXCEL_CSV'): Promise<AuditSummary> {
    const results: AssetAuditResult[] = [];

    // Collect all unique CVEs across assets for bulk EPSS query
    const allMatchedCves: NormalizedCve[] = [];

    for (const asset of assets) {
      const matchedCves = this.findVulnerabilitiesForAsset(asset);
      allMatchedCves.push(...matchedCves);
    }

    // Enrich with EPSS in bulk
    await epssService.enrichCves(allMatchedCves);

    for (const asset of assets) {
      const matchedCves = this.findVulnerabilitiesForAsset(asset);

      const zeroDays = matchedCves.filter((c) => c.isZeroDay || c.isCisaKev);
      const criticalCves = matchedCves.filter((c) => (c.cvssScore ?? 0) >= 9.0);

      let highestCvss = 0;
      let highestEpss = 0;

      for (const c of matchedCves) {
        if (c.cvssScore && c.cvssScore > highestCvss) {
          highestCvss = c.cvssScore;
        }
        if (c.epssScore && c.epssScore > highestEpss) {
          highestEpss = c.epssScore;
        }
      }

      let riskStatus: 'ACTIVE ZERO-DAY' | 'CRITICAL' | 'HIGH' | 'SAFE' = 'SAFE';
      if (zeroDays.length > 0) {
        riskStatus = 'ACTIVE ZERO-DAY';
      } else if (highestCvss >= 9.0 || criticalCves.length > 0) {
        riskStatus = 'CRITICAL';
      } else if (highestCvss >= 7.0) {
        riskStatus = 'HIGH';
      } else {
        riskStatus = 'SAFE';
      }

      results.push({
        asset,
        riskStatus,
        highestCvss,
        highestEpss,
        zeroDayCount: zeroDays.length,
        criticalCount: criticalCves.length,
        totalCveCount: matchedCves.length,
        matchedCves,
      });
    }

    // Sort: Zero-Day first, then Critical, then High, then Safe
    results.sort((a, b) => {
      const order = { 'ACTIVE ZERO-DAY': 0, 'CRITICAL': 1, 'HIGH': 2, 'SAFE': 3 };
      if (order[a.riskStatus] !== order[b.riskStatus]) {
        return order[a.riskStatus] - order[b.riskStatus];
      }
      return b.highestCvss - a.highestCvss;
    });

    const activeZeroDays = results.filter((r) => r.riskStatus === 'ACTIVE ZERO-DAY').length;
    const criticalAssets = results.filter((r) => r.riskStatus === 'CRITICAL').length;
    const highRiskAssets = results.filter((r) => r.riskStatus === 'HIGH').length;
    const safeAssets = results.filter((r) => r.riskStatus === 'SAFE').length;

    // Trigger notification if active zero-days were detected during scan
    if (activeZeroDays > 0) {
      const topZeroDay = results[0];
      const cveInfo = topZeroDay.matchedCves[0];
      alertService.sendTeamsAlert({
        title: `Inventory Audit Alert: ${activeZeroDays} Active Zero-Days Found!`,
        summary: `ThreatRadar scanned inventory and detected exploited zero-days targeting ${topZeroDay.asset.softwareName} on host ${topZeroDay.asset.host || 'network'}.`,
        cveId: cveInfo?.cveId,
        severity: 'CRITICAL',
        cvssScore: cveInfo?.cvssScore,
        epssScore: cveInfo?.epssScore,
        affectedEntity: `${topZeroDay.asset.softwareName} (${topZeroDay.asset.host})`,
        actionRequired: cveInfo?.requiredAction,
      }).catch((e) => console.warn('[Audit Alert] Teams notification skipped:', e.message));
    }

    return {
      totalAssets: results.length,
      activeZeroDays,
      criticalAssets,
      highRiskAssets,
      safeAssets,
      scannedAt: new Date().toISOString(),
      sourceFormat: format,
      results,
    };
  }

  /**
   * Correlates an individual asset against CISA KEV catalog and known CVEs
   */
  private findVulnerabilitiesForAsset(asset: AssetItem): NormalizedCve[] {
    const swName = asset.softwareName.toLowerCase();
    const matches: NormalizedCve[] = [];
    const seenCves = new Set<string>();

    // 1. Search in CISA KEV catalog
    const cisaMatches = cisaService.search(swName, 10);
    for (const item of cisaMatches) {
      if (!seenCves.has(item.cveID)) {
        seenCves.add(item.cveID);
        matches.push({
          cveId: item.cveID,
          title: item.vulnerabilityName,
          description: item.shortDescription,
          vendor: item.vendorProject,
          product: item.product,
          cvssScore: 9.8,
          severity: 'CRITICAL',
          publishedDate: `${item.dateAdded}T00:00:00.000Z`,
          lastModifiedDate: `${item.dueDate}T00:00:00.000Z`,
          isZeroDay: true,
          isCisaKev: true,
          isRansomware: item.knownRansomwareCampaignUse === 'Known',
          ransomwareCampaign: item.knownRansomwareCampaignUse === 'Known' ? 'Active In-The-Wild Exploitation' : undefined,
          requiredAction: item.requiredAction,
          dueDate: item.dueDate,
          attackVector: 'Network',
          references: [`https://nvd.nist.gov/vuln/detail/${item.cveID}`],
          remediation: item.requiredAction,
        });
      }
    }

    // 2. Search in curated database
    for (const item of CURATED_CVE_DATABASE) {
      const matchVendor = item.vendor.toLowerCase();
      const matchProduct = item.product.toLowerCase();

      if (
        swName.includes(matchVendor) ||
        swName.includes(matchProduct) ||
        matchProduct.includes(swName) ||
        matchVendor.includes(swName)
      ) {
        if (!seenCves.has(item.cveId)) {
          seenCves.add(item.cveId);
          matches.push(item);
        }
      }
    }

    return matches.sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
  }
}

export const auditService = new AuditService();
