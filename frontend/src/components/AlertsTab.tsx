import React, { useState, useEffect } from 'react';
import {
  Bell,
  Mail,
  Send,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ShieldAlert,
  Server,
  Save,
  MessageSquare,
} from 'lucide-react';
import { threatApi } from '../services/api';
import { AlertConfig } from '../types';

export const AlertsTab: React.FC = () => {
  const [config, setConfig] = useState<AlertConfig>({
    teamsWebhookUrl: '',
    teamsEnabled: false,
    smtpHost: '',
    smtpPort: 587,
    smtpUser: '',
    smtpPass: '',
    smtpFrom: 'ThreatRadar Alerts <alerts@threat-radar.local>',
    alertRecipients: '',
    emailEnabled: false,
    notifyOnZeroDay: true,
    notifyOnCritical: true,
  });

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [teamsTesting, setTeamsTesting] = useState(false);
  const [emailTesting, setEmailTesting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    threatApi
      .getAlertConfig()
      .then((cfg) => {
        if (cfg) setConfig(cfg);
      })
      .catch((err) => console.error('Failed to load alert config:', err))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setFeedback(null);
    try {
      const updated = await threatApi.updateAlertConfig(config);
      setConfig(updated);
      setFeedback({ type: 'success', message: 'Alert configuration saved successfully!' });
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Failed to save configuration.' });
    } finally {
      setSaving(false);
    }
  };

  const handleTestTeams = async () => {
    if (!config.teamsWebhookUrl) {
      setFeedback({ type: 'error', message: 'Please enter a valid Microsoft Teams Webhook URL first.' });
      return;
    }
    setTeamsTesting(true);
    setFeedback(null);
    try {
      const res = await threatApi.testTeamsAlert(config.teamsWebhookUrl);
      if (res.success) {
        setFeedback({ type: 'success', message: res.message || 'Test card successfully delivered to Microsoft Teams!' });
      } else {
        setFeedback({ type: 'error', message: res.message || 'Teams test failed.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.response?.data?.message || err.message });
    } finally {
      setTeamsTesting(false);
    }
  };

  const handleTestEmail = async () => {
    if (!config.alertRecipients) {
      setFeedback({ type: 'error', message: 'Please specify alert recipient email(s).' });
      return;
    }
    setEmailTesting(true);
    setFeedback(null);
    try {
      const res = await threatApi.testEmailAlert(config.alertRecipients);
      if (res.success) {
        setFeedback({
          type: 'success',
          message: res.simulated
            ? `Email simulated successfully for ${config.alertRecipients}. (Set SMTP_HOST to send live mail)`
            : `Live security email sent to ${config.alertRecipients}!`,
        });
      } else {
        setFeedback({ type: 'error', message: res.message || 'Email delivery failed.' });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.response?.data?.message || err.message });
    } finally {
      setEmailTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="cyber-card p-12 text-center font-mono text-xs text-slate-400">
        Loading integration configurations...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="cyber-card p-6 border-purple-900/40 bg-gradient-to-br from-[#12081c]/95 to-[#0b0f19]/95 relative overflow-hidden">
        <div className="flex items-center gap-2 mb-2">
          <span className="p-1.5 rounded-md bg-purple-950 border border-purple-700 text-purple-400">
            <Bell className="w-4 h-4" />
          </span>
          <h2 className="text-lg font-bold font-mono tracking-wide text-white">
            ENTERPRISE ALERTING & SEC-OPS INTEGRATIONS
          </h2>
        </div>
        <p className="text-xs text-slate-400 max-w-2xl font-sans leading-relaxed">
          Configure real-time automated dispatchers. Whenever a new high-profile zero-day is registered in the CISA KEV catalog or detected inside your scanned company inventory, ThreatRadar automatically transmits structured alerts with remediation guidance.
        </p>

        {feedback && (
          <div
            className={`mt-4 p-3 rounded-lg border text-xs font-mono flex items-center gap-2 ${
              feedback.type === 'success'
                ? 'bg-emerald-950/60 border-emerald-700 text-emerald-200'
                : 'bg-rose-950/60 border-rose-700 text-rose-200'
            }`}
          >
            {feedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            )}
            <span>{feedback.message}</span>
          </div>
        )}
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Module 1: Microsoft Teams Webhook */}
        <div className="cyber-card p-6 border-slate-800">
          <div className="flex items-center justify-between flex-wrap gap-2 mb-4">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-md bg-blue-950/60 border border-blue-700 text-blue-400">
                <MessageSquare className="w-4 h-4" />
              </span>
              <div>
                <h3 className="text-sm font-bold font-mono text-white">
                  MICROSOFT TEAMS INCOMING WEBHOOK
                </h3>
                <p className="text-xs text-slate-400">
                  Sends formatted Adaptive Cards directly into your SecOps or SOC Teams channel.
                </p>
              </div>
            </div>

            <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={config.teamsEnabled}
                onChange={(e) => setConfig({ ...config, teamsEnabled: e.target.checked })}
                className="rounded bg-slate-900 border-slate-700 text-indigo-500 focus:ring-0"
              />
              <span>Enable Teams Alerts</span>
            </label>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">
                Teams Incoming Webhook URL:
              </label>
              <input
                type="text"
                value={config.teamsWebhookUrl || ''}
                onChange={(e) => setConfig({ ...config, teamsWebhookUrl: e.target.value })}
                placeholder="https://yourcompany.webhook.office.com/webhookb2/..."
                className="w-full p-2.5 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleTestTeams}
                disabled={teamsTesting || !config.teamsWebhookUrl}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors disabled:opacity-40"
              >
                <Send className="w-3.5 h-3.5 text-blue-400" />
                <span>{teamsTesting ? 'Dispatching Test Card...' : 'Send Test Card to Teams'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Module 2: SMTP Email Alerts */}
        <div className="cyber-card p-6 border-slate-800">
          <div className="flex items-center justify-between flex-wrap gap-2 mb-4">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-md bg-purple-950/60 border border-purple-700 text-purple-400">
                <Mail className="w-4 h-4" />
              </span>
              <div>
                <h3 className="text-sm font-bold font-mono text-white">
                  SMTP EMAIL DISPATCHER
                </h3>
                <p className="text-xs text-slate-400">
                  Sends rich HTML Cyber-Ops security bulletins to your security mailing list.
                </p>
              </div>
            </div>

            <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={config.emailEnabled}
                onChange={(e) => setConfig({ ...config, emailEnabled: e.target.checked })}
                className="rounded bg-slate-900 border-slate-700 text-purple-500 focus:ring-0"
              />
              <span>Enable Email Alerts</span>
            </label>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                SMTP Host Server:
              </label>
              <input
                type="text"
                value={config.smtpHost || ''}
                onChange={(e) => setConfig({ ...config, smtpHost: e.target.value })}
                placeholder="e.g. mail.corp.com or smtp.gmail.com"
                className="w-full p-2 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                SMTP Port:
              </label>
              <input
                type="number"
                value={config.smtpPort || 587}
                onChange={(e) => setConfig({ ...config, smtpPort: parseInt(e.target.value, 10) || 587 })}
                className="w-full p-2 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                Username:
              </label>
              <input
                type="text"
                value={config.smtpUser || ''}
                onChange={(e) => setConfig({ ...config, smtpUser: e.target.value })}
                placeholder="alerts@company.com"
                className="w-full p-2 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                Password / App Token:
              </label>
              <input
                type="password"
                value={config.smtpPass || ''}
                onChange={(e) => setConfig({ ...config, smtpPass: e.target.value })}
                placeholder="••••••••••••"
                className="w-full p-2 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="text-[11px] font-mono text-slate-400 block mb-1">
                Recipient Email Addresses (comma separated):
              </label>
              <input
                type="text"
                value={config.alertRecipients || ''}
                onChange={(e) => setConfig({ ...config, alertRecipients: e.target.value })}
                placeholder="secops@company.com, ciso@company.com"
                className="w-full p-2 bg-[#030712] border border-slate-700 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>

          <div className="mt-3 flex justify-end">
            <button
              type="button"
              onClick={handleTestEmail}
              disabled={emailTesting || !config.alertRecipients}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors disabled:opacity-40"
            >
              <Mail className="w-3.5 h-3.5 text-purple-400" />
              <span>{emailTesting ? 'Transmitting Email...' : 'Send Test Email Bulletin'}</span>
            </button>
          </div>
        </div>

        {/* Module 3: Automated Triggers & Save */}
        <div className="cyber-card p-6 border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={config.notifyOnZeroDay}
                onChange={(e) => setConfig({ ...config, notifyOnZeroDay: e.target.checked })}
                className="rounded bg-slate-900 border-slate-700 text-rose-500"
              />
              <span>Auto-dispatch notification when a new CISA Zero-Day is published</span>
            </label>

            <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={config.notifyOnCritical}
                onChange={(e) => setConfig({ ...config, notifyOnCritical: e.target.checked })}
                className="rounded bg-slate-900 border-slate-700 text-amber-500"
              />
              <span>Auto-dispatch alert if uploaded Inventory contains an Active Zero-Day</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 text-white text-xs font-mono font-bold tracking-wider flex items-center gap-2 shadow-lg shadow-emerald-950 transition-all disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'SAVING...' : 'SAVE INTEGRATION SETTINGS'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
