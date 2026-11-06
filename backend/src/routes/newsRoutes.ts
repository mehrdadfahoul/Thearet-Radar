import { Router, Request, Response } from 'express';
import { cisaService } from '../services/cisaService.js';
import { gitHubAdvisoryService } from '../services/githubAdvisoryService.js';
import { epssService } from '../services/epssService.js';
import { UnifiedThreatNews } from '../types.js';

const router = Router();

// GET /api/news - Get merged live threat news feed & stats
router.get('/', async (req: Request, res: Response) => {
  try {
    const ghsaNews = await gitHubAdvisoryService.getAdvisories();
    const cisaRecent = cisaService.getRecent(20);

    // Convert CISA items to UnifiedThreatNews format
    const cisaNews: UnifiedThreatNews[] = cisaRecent.map((k) => {
      const addedDate = new Date(`${k.dateAdded}T00:00:00.000Z`);
      const now = new Date();
      const diffDays = Math.floor((now.getTime() - addedDate.getTime()) / (1000 * 60 * 60 * 24));
      const humanizedDate = diffDays <= 0 ? 'Today' : diffDays === 1 ? 'Yesterday' : `${diffDays} days ago`;

      return {
        id: k.cveID,
        cveId: k.cveID,
        title: k.vulnerabilityName,
        summary: k.shortDescription,
        vendor: k.vendorProject,
        product: k.product,
        severity: 'CRITICAL',
        cvssScore: 9.8,
        publishedAt: `${k.dateAdded}T00:00:00.000Z`,
        humanizedDate,
        isZeroDay: true,
        isCisaKev: true,
        isRansomware: k.knownRansomwareCampaignUse === 'Known',
        ransomwareCampaign: k.knownRansomwareCampaignUse === 'Known' ? 'Known Ransomware Campaign' : undefined,
        requiredAction: k.requiredAction,
        source: 'CISA KEV',
        bulletinUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${k.cveID}`,
        attackVector: 'Wild Active Exploitation',
      };
    });

    // Merge and de-duplicate by cveId/id
    const combined: UnifiedThreatNews[] = [];
    const seen = new Set<string>();

    for (const item of cisaNews) {
      const key = (item.cveId || item.id).toUpperCase();
      if (!seen.has(key)) {
        seen.add(key);
        combined.push(item);
      }
    }

    for (const item of ghsaNews) {
      const key = (item.cveId || item.id).toUpperCase();
      if (!seen.has(key)) {
        seen.add(key);
        combined.push(item);
      }
    }

    // Sort descending by publishedAt
    combined.sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime());

    // Enrich with EPSS exploit prediction scores
    await epssService.enrichThreatNews(combined);

    const cisaStatus = cisaService.getStatus();

    res.json({
      success: true,
      stats: {
        totalThreats: combined.length,
        totalCisaKev: cisaStatus.totalKevCount,
        lastSync: cisaStatus.lastSyncTime,
        activeZeroDaysCount: combined.filter((i) => i.isZeroDay).length,
        ransomwareTargetsCount: combined.filter((i) => i.isRansomware).length,
      },
      feed: combined,
    });
  } catch (error: any) {
    console.error('[API /api/news] Error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/news/ticker - Get top active zero-days for marquee banner
router.get('/ticker', async (req: Request, res: Response) => {
  try {
    const recent = cisaService.getRecent(10);
    const tickerItems = recent.map((item) => ({
      cveId: item.cveID,
      title: item.vulnerabilityName,
      vendor: item.vendorProject,
      product: item.product,
      dateAdded: item.dateAdded,
      isRansomware: item.knownRansomwareCampaignUse === 'Known',
    }));

    res.json({
      success: true,
      ticker: tickerItems,
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
