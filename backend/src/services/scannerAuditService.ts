import { AssetItem, NormalizedCve } from '../types.js';
import { cisaService } from './cisaService.js';
import { CURATED_CVE_DATABASE } from './sampleData.js';

export class ScannerAuditService {
  /**
   * Parse Nmap XML output into standardized AssetItem list
   */
  public parseNmapXml(xmlContent: string): AssetItem[] {
    const assets: AssetItem[] = [];
    const hostRegex = /<host[\s\S]*?<\/host>/g;
    const hosts = xmlContent.match(hostRegex) || [];

    for (const hostBlock of hosts) {
      // Extract IP / Address
      const addrMatch = hostBlock.match(/<address[^>]*addr="([^"]+)"[^>]*addrtype="ipv4"/i) ||
                        hostBlock.match(/<address[^>]*addr="([^"]+)"/i);
      const hostIp = addrMatch ? addrMatch[1] : 'Unknown Host';

      // Extract hostname
      const hostNameMatch = hostBlock.match(/<hostname[^>]*name="([^"]+)"/i);
      const hostLabel = hostNameMatch ? `${hostNameMatch[1]} (${hostIp})` : hostIp;

      // Extract OS if available
      const osMatch = hostBlock.match(/<osmatch[^>]*name="([^"]+)"/i);
      const osInfo = osMatch ? osMatch[1] : 'Network Device / Server';

      // Extract open ports and services
      const portRegex = /<port[\s\S]*?<\/port>/g;
      const portBlocks = hostBlock.match(portRegex) || [];

      for (const portBlock of portBlocks) {
        // Only process open ports
        if (!/<state[^>]*state="open"/i.test(portBlock)) continue;

        const portIdMatch = portBlock.match(/portid="(\d+)"/i);
        const protocolMatch = portBlock.match(/protocol="([^"]+)"/i);
        const portNum = portIdMatch ? portIdMatch[1] : '';
        const protocol = protocolMatch ? protocolMatch[1] : 'tcp';

        const serviceMatch = portBlock.match(/<service([^>]*)\/?>/i);
        if (serviceMatch) {
          const serviceAttrs = serviceMatch[1];
          const nameAttr = serviceAttrs.match(/name="([^"]+)"/i);
          const productAttr = serviceAttrs.match(/product="([^"]+)"/i);
          const versionAttr = serviceAttrs.match(/version="([^"]+)"/i);
          const extraAttr = serviceAttrs.match(/extrainfo="([^"]+)"/i);

          const productName = productAttr ? productAttr[1] : nameAttr ? nameAttr[1] : 'Network Service';
          const version = versionAttr ? versionAttr[1] : extraAttr ? extraAttr[1] : undefined;

          assets.push({
            softwareName: productName,
            version,
            category: `Port ${portNum}/${protocol.toUpperCase()} Service`,
            department: 'Network Operations (Nmap Scan)',
            host: hostLabel,
            port: portNum,
            source: 'NMAP',
            rawRow: {
              Scanner: 'Nmap',
              Port: `${portNum}/${protocol}`,
              Service: productName,
              Version: version || 'N/A',
              Host: hostLabel,
              OS: osInfo,
            },
          });
        }
      }
    }

    return assets;
  }

  /**
   * Parse Nessus XML (.nessus) scan results
   */
  public parseNessusXml(xmlContent: string): {
    assets: AssetItem[];
    detectedCves: Array<{ cve: string; host: string; port: string; name: string; solution?: string }>;
  } {
    const assets: AssetItem[] = [];
    const detectedCves: Array<{ cve: string; host: string; port: string; name: string; solution?: string }> = [];

    const hostRegex = /<ReportHost[\s\S]*?<\/ReportHost>/g;
    const hostBlocks = xmlContent.match(hostRegex) || [];

    for (const hostBlock of hostBlocks) {
      const hostNameMatch = hostBlock.match(/name="([^"]+)"/i);
      const hostName = hostNameMatch ? hostNameMatch[1] : 'Unknown Target';

      const itemRegex = /<ReportItem[\s\S]*?<\/ReportItem>/g;
      const items = hostBlock.match(itemRegex) || [];

      const seenServices = new Set<string>();

      for (const itemBlock of items) {
        const portMatch = itemBlock.match(/port="(\d+)"/i);
        const svcMatch = itemBlock.match(/svc_name="([^"]+)"/i);
        const pluginNameMatch = itemBlock.match(/pluginName="([^"]+)"/i);
        const solutionMatch = itemBlock.match(/<solution>([\s\S]*?)<\/solution>/i);

        const port = portMatch ? portMatch[1] : '0';
        const svc = svcMatch ? svcMatch[1] : 'service';
        const pluginName = pluginNameMatch ? pluginNameMatch[1] : 'Vulnerability';
        const solution = solutionMatch ? solutionMatch[1].trim() : undefined;

        // Extract CVEs inside this ReportItem
        const cveMatches = itemBlock.match(/<cve>(CVE-\d{4}-\d{4,})<\/cve>/gi) || [];
        for (const cveTag of cveMatches) {
          const cveIdMatch = cveTag.match(/CVE-\d{4}-\d{4,}/i);
          if (cveIdMatch) {
            detectedCves.push({
              cve: cveIdMatch[0].toUpperCase(),
              host: hostName,
              port,
              name: pluginName,
              solution,
            });
          }
        }

        // Add to assets
        const key = `${hostName}-${port}-${svc}`;
        if (!seenServices.has(key)) {
          seenServices.add(key);
          assets.push({
            softwareName: pluginName.split(':')[0] || svc,
            version: undefined,
            category: `Nessus Finding (Port ${port})`,
            department: 'SecOps (Nessus Scanner)',
            host: hostName,
            port,
            source: 'NESSUS',
            rawRow: {
              Host: hostName,
              Port: port,
              Service: svc,
              Plugin: pluginName,
            },
          });
        }
      }
    }

    return { assets, detectedCves };
  }

  /**
   * Parse Nessus CSV export
   */
  public parseNessusCsv(csvRows: Record<string, any>[]): {
    assets: AssetItem[];
    detectedCves: Array<{ cve: string; host: string; port: string; name: string }>;
  } {
    const assets: AssetItem[] = [];
    const detectedCves: Array<{ cve: string; host: string; port: string; name: string }> = [];
    const seen = new Set<string>();

    for (const row of csvRows) {
      const cveField = row['CVE'] || row['cve'] || '';
      const host = row['Host'] || row['host'] || row['IP Address'] || 'Endpoint';
      const port = row['Port'] || row['port'] || '0';
      const name = row['Name'] || row['name'] || row['Plugin Name'] || 'Vulnerability Finding';

      if (cveField && typeof cveField === 'string') {
        const cves = cveField.split(',').map((c) => c.trim()).filter((c) => c.toUpperCase().startsWith('CVE-'));
        for (const c of cves) {
          detectedCves.push({
            cve: c.toUpperCase(),
            host,
            port: String(port),
            name,
          });
        }
      }

      const key = `${host}-${name}`;
      if (!seen.has(key)) {
        seen.add(key);
        assets.push({
          softwareName: name,
          version: undefined,
          category: `Port ${port} Target`,
          department: 'SecOps (Nessus CSV)',
          host,
          port,
          source: 'NESSUS',
          rawRow: row,
        });
      }
    }

    return { assets, detectedCves };
  }
}

export const scannerAuditService = new ScannerAuditService();
