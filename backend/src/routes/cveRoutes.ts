import { Router, Request, Response } from 'express';
import { nvdService } from '../services/nvdService.js';
import { SAMPLE_CSV_TEMPLATE } from '../services/sampleData.js';
import { cisaService } from '../services/cisaService.js';
import { epssService } from '../services/epssService.js';

const router = Router();

// GET /api/cve/search - Smart tail search or trending CVEs
router.get('/search', async (req: Request, res: Response) => {
  try {
    const query = String(req.query.q || '').trim();
    const limit = parseInt(String(req.query.limit || '20'), 10) || 20;

    const results = await nvdService.searchCves(query, limit);
    await epssService.enrichCves(results);

    res.json({
      success: true,
      query,
      count: results.length,
      results,
    });
  } catch (error: any) {
    console.error('[API /api/cve/search] Error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/cve/sample-template - Download ready-to-use CSV template
router.get('/sample-template', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="threat_radar_sample_inventory.csv"');
  res.send(SAMPLE_CSV_TEMPLATE);
});

// GET /api/cve/details/:cveId - Inspect single CVE
router.get('/details/:cveId', async (req: Request, res: Response) => {
  try {
    const rawId = req.params.cveId;
    const cveId = (Array.isArray(rawId) ? rawId[0] : rawId || '').toUpperCase().trim();
    const results = await nvdService.searchCves(cveId, 1);

    if (results.length > 0) {
      res.json({ success: true, cve: results[0] });
    } else {
      // Check CISA directly
      const cisaItem = cisaService.getByCve(cveId);
      if (cisaItem) {
        res.json({
          success: true,
          cve: {
            cveId: cisaItem.cveID,
            title: cisaItem.vulnerabilityName,
            description: cisaItem.shortDescription,
            vendor: cisaItem.vendorProject,
            product: cisaItem.product,
            cvssScore: 9.8,
            severity: 'CRITICAL',
            publishedDate: `${cisaItem.dateAdded}T00:00:00.000Z`,
            lastModifiedDate: `${cisaItem.dueDate}T00:00:00.000Z`,
            isZeroDay: true,
            isCisaKev: true,
            isRansomware: cisaItem.knownRansomwareCampaignUse === 'Known',
            requiredAction: cisaItem.requiredAction,
            dueDate: cisaItem.dueDate,
            attackVector: 'Network',
            references: [`https://nvd.nist.gov/vuln/detail/${cisaItem.cveID}`],
            remediation: cisaItem.requiredAction,
          },
        });
      } else {
        res.status(404).json({ success: false, message: `CVE record ${cveId} not found.` });
      }
    }
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
