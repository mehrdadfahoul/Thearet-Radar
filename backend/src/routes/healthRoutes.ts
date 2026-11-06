import { Router, Request, Response } from 'express';
import { cisaService } from '../services/cisaService.js';

const router = Router();

router.get('/', (_req: Request, res: Response) => {
  const cisaStatus = cisaService.getStatus();

  res.json({
    status: 'OPERATIONAL',
    platform: 'ThreatRadar CTI Engine',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    feeds: {
      cisaKev: {
        status: cisaStatus.status,
        count: cisaStatus.totalKevCount,
        lastSync: cisaStatus.lastSyncTime,
        resyncIntervalHours: 6,
      },
      githubAdvisories: {
        status: 'ACTIVE',
        cacheDurationMinutes: 10,
      },
      nvdApiV2: {
        status: 'ACTIVE',
        mode: 'Smart Tail Fetching (Ascending order reversed)',
      },
    },
  });
});

export default router;
