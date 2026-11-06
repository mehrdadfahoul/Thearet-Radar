import { Router, Request, Response } from 'express';
import multer from 'multer';
import { auditService } from '../services/auditService.js';
import { DEMO_INVENTORY_ASSETS } from '../services/sampleData.js';

const router = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// POST /api/audit/upload - Process Excel/CSV software inventory upload
router.post('/upload', upload.single('file'), async (req: Request, res: Response) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded. Please upload a valid .xlsx, .xls, or .csv file.',
      });
    }

    console.log(`[Audit] Processing uploaded file: ${req.file.originalname} (${req.file.size} bytes)`);
    const { assets, format } = auditService.parseUploadedFile(req.file.buffer, req.file.originalname);

    if (assets.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No software assets or vulnerability findings could be parsed from the uploaded file.',
      });
    }

    console.log(`[Audit] Successfully parsed ${assets.length} assets from ${format}. Running vulnerability and EPSS correlation...`);
    const summary = await auditService.auditAssets(assets, format);

    res.json({
      success: true,
      filename: req.file.originalname,
      format,
      summary,
    });
  } catch (error: any) {
    console.error('[API /api/audit/upload] Error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to process software inventory audit.',
    });
  }
});

// GET /api/audit/demo - Run audit on pre-configured enterprise demo inventory
router.get('/demo', async (_req: Request, res: Response) => {
  try {
    console.log('[Audit] Generating demo enterprise audit report...');
    const summary = await auditService.auditAssets(DEMO_INVENTORY_ASSETS);

    res.json({
      success: true,
      filename: 'enterprise_production_assets_demo.xlsx',
      summary,
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

export default router;
