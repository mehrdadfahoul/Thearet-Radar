import { Router, Request, Response } from 'express';
import multer from 'multer';
import { ipThreatService } from '../services/ipThreatService.js';
import { threatHunterService } from '../services/threatHunterService.js';

const router = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 30 * 1024 * 1024 }, // 30MB limit for suspicious file check
});

// GET /api/threat-intel/ip/status - Live feed stats
router.get('/ip/status', (_req: Request, res: Response) => {
  res.json({
    success: true,
    feed: ipThreatService.getFeedStatus(),
  });
});

// GET /api/threat-intel/ip/check - Check single IP
router.get('/ip/check', (req: Request, res: Response) => {
  const ip = String(req.query.ip || '').trim();
  if (!ip) {
    return res.status(400).json({ success: false, error: 'Query parameter "ip" is required.' });
  }

  const result = ipThreatService.checkIp(ip);
  res.json({
    success: true,
    result,
  });
});

// POST /api/threat-intel/ip/bulk-scan - Scan log text for malicious IPs
router.post('/ip/bulk-scan', (req: Request, res: Response) => {
  const logContent = String(req.body.logs || req.body.text || '').trim();
  if (!logContent) {
    return res.status(400).json({ success: false, error: 'Field "logs" is required.' });
  }

  const result = ipThreatService.bulkScanLogs(logContent);
  res.json({
    success: true,
    result,
  });
});

// POST /api/threat-intel/scan-file - VirusTotal style file hash scanning
router.post('/scan-file', upload.single('file'), async (req: Request, res: Response) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded.' });
    }

    const result = await threatHunterService.scanFile(req.file.buffer, req.file.originalname);
    res.json({
      success: true,
      result,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/threat-intel/scan-url - VirusTotal style URL scan
router.post('/scan-url', async (req: Request, res: Response) => {
  try {
    const targetUrl = String(req.body.url || '').trim();
    if (!targetUrl) {
      return res.status(400).json({ success: false, error: 'Field "url" is required.' });
    }

    const result = await threatHunterService.scanUrl(targetUrl);
    res.json({
      success: true,
      result,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
