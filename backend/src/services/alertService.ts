import axios from 'axios';
import net from 'net';
import tls from 'tls';
import { AlertConfig } from '../types.js';

class AlertService {
  private config: AlertConfig = {
    teamsWebhookUrl: process.env.TEAMS_WEBHOOK_URL || '',
    teamsEnabled: Boolean(process.env.TEAMS_WEBHOOK_URL),
    smtpHost: process.env.SMTP_HOST || '',
    smtpPort: parseInt(process.env.SMTP_PORT || '587', 10),
    smtpUser: process.env.SMTP_USER || '',
    smtpPass: process.env.SMTP_PASS || '',
    smtpFrom: process.env.SMTP_FROM || 'ThreatRadar Alerts <alerts@threat-radar.local>',
    alertRecipients: process.env.ALERT_RECIPIENTS || '',
    emailEnabled: Boolean(process.env.SMTP_HOST && process.env.ALERT_RECIPIENTS),
    notifyOnZeroDay: true,
    notifyOnCritical: true,
  };

  public getConfig(): AlertConfig {
    return {
      ...this.config,
      smtpPass: this.config.smtpPass ? '********' : '', // Mask secret in response
    };
  }

  public updateConfig(newConfig: Partial<AlertConfig>): AlertConfig {
    if (newConfig.teamsWebhookUrl !== undefined) this.config.teamsWebhookUrl = newConfig.teamsWebhookUrl;
    if (newConfig.teamsEnabled !== undefined) this.config.teamsEnabled = newConfig.teamsEnabled;
    if (newConfig.smtpHost !== undefined) this.config.smtpHost = newConfig.smtpHost;
    if (newConfig.smtpPort !== undefined) this.config.smtpPort = newConfig.smtpPort;
    if (newConfig.smtpUser !== undefined) this.config.smtpUser = newConfig.smtpUser;
    if (newConfig.smtpPass && newConfig.smtpPass !== '********') this.config.smtpPass = newConfig.smtpPass;
    if (newConfig.smtpFrom !== undefined) this.config.smtpFrom = newConfig.smtpFrom;
    if (newConfig.alertRecipients !== undefined) this.config.alertRecipients = newConfig.alertRecipients;
    if (newConfig.emailEnabled !== undefined) this.config.emailEnabled = newConfig.emailEnabled;
    if (newConfig.notifyOnZeroDay !== undefined) this.config.notifyOnZeroDay = newConfig.notifyOnZeroDay;
    if (newConfig.notifyOnCritical !== undefined) this.config.notifyOnCritical = newConfig.notifyOnCritical;

    console.log('[AlertService] Alert configuration updated.');
    return this.getConfig();
  }

  /**
   * Send notification to Microsoft Teams via Incoming Webhook (Adaptive Card / Connector format)
   */
  public async sendTeamsAlert(data: {
    title: string;
    summary: string;
    cveId?: string;
    severity?: string;
    cvssScore?: number | null;
    epssScore?: number | null;
    affectedEntity?: string;
    actionRequired?: string;
    customWebhookUrl?: string;
  }): Promise<{ success: boolean; message: string }> {
    const webhookUrl = data.customWebhookUrl || this.config.teamsWebhookUrl;

    if (!webhookUrl || !webhookUrl.trim()) {
      return { success: false, message: 'Microsoft Teams Webhook URL is not configured.' };
    }

    const themeColor = data.severity === 'CRITICAL' ? 'd9383a' : 'ea580c';
    const epssPct = data.epssScore ? `${(data.epssScore * 100).toFixed(1)}%` : 'N/A';

    // Standard Office 365 Connector Card for Microsoft Teams
    const teamsCard = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor,
      summary: data.title,
      sections: [
        {
          activityTitle: `🚨 **THREAT RADAR ALERT**: ${data.title}`,
          activitySubtitle: `Published: ${new Date().toUTCString()} | Source: ThreatRadar Engine`,
          activityImage: 'https://img.icons8.com/color/96/shield.png',
          facts: [
            { name: 'Vulnerability / CVE:', value: data.cveId || 'Active Threat In-The-Wild' },
            { name: 'Severity Level:', value: `${data.severity || 'CRITICAL'} (CVSS: ${data.cvssScore?.toFixed(1) || '9.8'})` },
            { name: 'EPSS Exploit Probability:', value: `${epssPct} (Next 30 Days)` },
            { name: 'Affected Software:', value: data.affectedEntity || 'Enterprise Asset' },
            { name: 'Remediation Action:', value: data.actionRequired || 'Apply immediate vendor security update.' },
          ],
          markdown: true,
          text: data.summary,
        },
      ],
      potentialAction: [
        {
          '@type': 'OpenUri',
          name: 'Inspect in CISA / NVD',
          targets: [{ os: 'default', uri: data.cveId ? `https://nvd.nist.gov/vuln/detail/${data.cveId}` : 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }],
        },
      ],
    };

    try {
      console.log(`[AlertService] Dispatching alert to Microsoft Teams: "${data.title}"...`);
      const response = await axios.post(webhookUrl, teamsCard, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000,
      });

      if (response.status >= 200 && response.status < 300) {
        return { success: true, message: 'Successfully dispatched alert to Microsoft Teams!' };
      }
      return { success: false, message: `Teams returned status ${response.status}: ${response.statusText}` };
    } catch (err: any) {
      console.error('[AlertService] Failed to send Teams alert:', err.message);
      return { success: false, message: `Error sending to Teams: ${err.message}` };
    }
  }

  /**
   * Send Email Alert via native Node.js SMTP or simulation
   */
  public async sendEmailAlert(data: {
    title: string;
    summary: string;
    cveId?: string;
    severity?: string;
    cvssScore?: number | null;
    epssScore?: number | null;
    affectedEntity?: string;
    actionRequired?: string;
    customRecipients?: string;
  }): Promise<{ success: boolean; message: string; simulated?: boolean }> {
    const recipients = data.customRecipients || this.config.alertRecipients;

    if (!recipients || !recipients.trim()) {
      return { success: false, message: 'No alert recipients configured.' };
    }

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #030712; color: #f1f5f9; padding: 24px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #0b0f19; border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
          <div style="background: linear-gradient(90deg, #991b1b, #030712); padding: 16px 24px; border-bottom: 2px solid #ef4444;">
            <h2 style="margin: 0; color: #ffffff; font-size: 18px; letter-spacing: 1px;">⚡ THREAT RADAR // CRITICAL SECURITY BULLETIN</h2>
          </div>
          <div style="padding: 24px;">
            <h3 style="color: #f87171; margin-top: 0;">${data.title}</h3>
            <p style="color: #cbd5e1; line-height: 1.6; font-size: 14px;">${data.summary}</p>
            <div style="background-color: #111827; border: 1px solid #374151; border-radius: 8px; padding: 16px; margin: 20px 0;">
              <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <tr><td style="color: #94a3b8; padding: 4px 0;">CVE Identifier:</td><td style="color: #f87171; font-weight: bold;">${data.cveId || 'Active Zero-Day'}</td></tr>
                <tr><td style="color: #94a3b8; padding: 4px 0;">Severity / CVSS:</td><td style="color: #f59e0b; font-weight: bold;">${data.severity || 'CRITICAL'} (${data.cvssScore?.toFixed(1) || '9.8'})</td></tr>
                <tr><td style="color: #94a3b8; padding: 4px 0;">EPSS Exploit Probability:</td><td style="color: #38bdf8; font-weight: bold;">${data.epssScore ? (data.epssScore * 100).toFixed(1) + '%' : 'N/A'}</td></tr>
                <tr><td style="color: #94a3b8; padding: 4px 0;">Affected Entity:</td><td style="color: #f1f5f9;">${data.affectedEntity || 'General Infrastructure'}</td></tr>
              </table>
            </div>
            <div style="background-color: #064e3b; border: 1px solid #059669; border-radius: 8px; padding: 14px; color: #6ee7b7; font-size: 13px; line-height: 1.5;">
              <strong style="color: #34d399; display: block; margin-bottom: 4px;">REQUIRED MITIGATION:</strong>
              ${data.actionRequired || 'Immediately inspect affected infrastructure and upgrade to vendor patched release.'}
            </div>
          </div>
          <div style="background-color: #060a14; padding: 12px 24px; border-top: 1px solid #1f2937; font-size: 11px; color: #64748b; text-align: center;">
            ThreatRadar Automated Security Dispatcher • Standalone CTI Engine
          </div>
        </div>
      </body>
      </html>
    `;

    // If SMTP host is not configured, simulate delivery for safe preview
    if (!this.config.smtpHost) {
      console.log(`[AlertService] (Simulated Email) Dispatching to ${recipients}: "${data.title}"`);
      return {
        success: true,
        simulated: true,
        message: `Email alert simulated for ${recipients}. (To send real emails, specify SMTP_HOST in Settings)`,
      };
    }

    try {
      await this.sendRawSmtp({
        host: this.config.smtpHost,
        port: this.config.smtpPort || 587,
        user: this.config.smtpUser || '',
        pass: this.config.smtpPass || '',
        from: this.config.smtpFrom || 'alerts@threat-radar.local',
        to: recipients,
        subject: `[CRITICAL THREAT ALERT] ${data.title}`,
        html: htmlContent,
      });

      return { success: true, message: `Email alert successfully delivered to ${recipients}!` };
    } catch (err: any) {
      console.error('[AlertService] SMTP send error:', err.message);
      return { success: false, message: `SMTP transmission failed: ${err.message}` };
    }
  }

  /**
   * Minimal native SMTP sender via Node sockets
   */
  private sendRawSmtp(opts: {
    host: string;
    port: number;
    user: string;
    pass: string;
    from: string;
    to: string;
    subject: string;
    html: string;
  }): Promise<void> {
    return new Promise((resolve, reject) => {
      const isSecure = opts.port === 465;
      const socket = isSecure
        ? tls.connect({ host: opts.host, port: opts.port, rejectUnauthorized: false })
        : net.connect({ host: opts.host, port: opts.port });

      socket.setTimeout(15000);

      let step = 0;
      const recipientList = opts.to.split(',').map((r) => r.trim());

      socket.on('data', (chunk) => {
        const response = chunk.toString();

        if (response.startsWith('4') || response.startsWith('5')) {
          socket.destroy();
          return reject(new Error(`SMTP error: ${response.trim()}`));
        }

        switch (step) {
          case 0: // Connected
            socket.write(`EHLO threat-radar.local\r\n`);
            step++;
            break;
          case 1: // After EHLO
            if (opts.user && opts.pass) {
              socket.write(`AUTH LOGIN\r\n`);
              step = 2;
            } else {
              socket.write(`MAIL FROM:<${opts.from}>\r\n`);
              step = 4;
            }
            break;
          case 2: // Enter Username base64
            socket.write(Buffer.from(opts.user).toString('base64') + '\r\n');
            step = 3;
            break;
          case 3: // Enter Password base64
            socket.write(Buffer.from(opts.pass).toString('base64') + '\r\n');
            step = 4;
            break;
          case 4: // Auth done, Mail From
            socket.write(`MAIL FROM:<${opts.from}>\r\n`);
            step = 5;
            break;
          case 5: // Rcpt To
            const nextRcpt = recipientList.pop();
            if (nextRcpt) {
              socket.write(`RCPT TO:<${nextRcpt}>\r\n`);
              if (recipientList.length === 0) {
                step = 6;
              }
            } else {
              socket.write(`DATA\r\n`);
              step = 7;
            }
            break;
          case 6: // After RCPT TO
            socket.write(`DATA\r\n`);
            step = 7;
            break;
          case 7: // Send Message Body
            const rawMessage = [
              `From: ${opts.from}`,
              `To: ${opts.to}`,
              `Subject: ${opts.subject}`,
              `MIME-Version: 1.0`,
              `Content-Type: text/html; charset=UTF-8`,
              ``,
              opts.html,
              `.`,
              ``,
            ].join('\r\n');
            socket.write(rawMessage);
            step = 8;
            break;
          case 8: // After DATA accepted
            socket.write(`QUIT\r\n`);
            socket.end();
            resolve();
            break;
        }
      });

      socket.on('error', (err) => reject(err));
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('SMTP connection timed out after 15s.'));
      });
    });
  }
}

export const alertService = new AlertService();
