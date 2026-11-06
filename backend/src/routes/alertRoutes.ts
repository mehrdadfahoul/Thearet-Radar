import { Router, Request, Response } from 'express';
import { alertService } from '../services/alertService.js';

const router = Router();

// GET /api/alerts/config - Retrieve current configuration
router.get('/config', (_req: Request, res: Response) => {
  res.json({
    success: true,
    config: alertService.getConfig(),
  });
});

// POST /api/alerts/config - Update configuration
router.post('/config', (req: Request, res: Response) => {
  try {
    const updated = alertService.updateConfig(req.body);
    res.json({
      success: true,
      config: updated,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/alerts/test-teams - Dispatch test alert to Microsoft Teams
router.post('/test-teams', async (req: Request, res: Response) => {
  try {
    const webhookUrl = req.body.webhookUrl;
    const result = await alertService.sendTeamsAlert({
      title: 'ThreatRadar Test Alert // Microsoft Teams Integration',
      summary: 'This is a test notification confirming your Microsoft Teams Incoming Webhook is properly configured and operational.',
      cveId: 'CVE-2024-6387',
      severity: 'CRITICAL',
      cvssScore: 9.8,
      epssScore: 0.942,
      affectedEntity: 'OpenSSH Server (regreSSHion)',
      actionRequired: 'Test successful. ThreatRadar will broadcast critical zero-days to this channel.',
      customWebhookUrl: webhookUrl,
    });

    res.json(result);
  } catch (err: any) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/alerts/test-email - Dispatch test email alert
router.post('/test-email', async (req: Request, res: Response) => {
  try {
    const recipients = req.body.recipients;
    const result = await alertService.sendEmailAlert({
      title: 'ThreatRadar Test Security Alert // SMTP Integration',
      summary: 'This is a verification bulletin confirming your ThreatRadar email dispatch configuration is active.',
      cveId: 'CVE-2024-21762',
      severity: 'CRITICAL',
      cvssScore: 9.8,
      epssScore: 0.971,
      affectedEntity: 'Fortinet FortiOS SSL-VPN',
      actionRequired: 'Verify message formatting in your corporate email inbox.',
      customRecipients: recipients,
    });

    res.json(result);
  } catch (err: any) {
    res.status(500).json({ success: false, message: err.message });
  }
});

export default router;
