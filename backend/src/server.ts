import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import newsRoutes from './routes/newsRoutes.js';
import cveRoutes from './routes/cveRoutes.js';
import auditRoutes from './routes/auditRoutes.js';
import healthRoutes from './routes/healthRoutes.js';
import threatIntelRoutes from './routes/threatIntelRoutes.js';
import alertRoutes from './routes/alertRoutes.js';
import { cisaService } from './services/cisaService.js';
import { gitHubAdvisoryService } from './services/githubAdvisoryService.js';
import { ipThreatService } from './services/ipThreatService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// API Routes
app.use('/api/news', newsRoutes);
app.use('/api/cve', cveRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/threat-intel', threatIntelRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/health', healthRoutes);

// In production, serve the frontend build from frontend/dist
const frontendDistPath = path.resolve(__dirname, '../../frontend/dist');
if (fs.existsSync(frontendDistPath)) {
  console.log(`[Static] Serving frontend static assets from: ${frontendDistPath}`);
  app.use(express.static(frontendDistPath));

  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.sendFile(path.join(frontendDistPath, 'index.html'));
  });
} else {
  app.get('/', (_req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>ThreatRadar API Active</title></head>
        <body style="background:#030712;color:#f1f5f9;font-family:monospace;padding:40px;">
          <h1 style="color:#f43f5e;">// ThreatRadar CTI Engine Active</h1>
          <p>API endpoints running on port ${PORT}:</p>
          <ul>
            <li><a style="color:#38bdf8;" href="/api/health">/api/health</a> - System Health & Feed Sync</li>
            <li><a style="color:#38bdf8;" href="/api/news">/api/news</a> - Live Threat News & Zero-Days</li>
            <li><a style="color:#38bdf8;" href="/api/cve/search?q=fortinet">/api/cve/search?q=fortinet</a> - Smart Tail CVE Search</li>
            <li><a style="color:#38bdf8;" href="/api/cve/sample-template">/api/cve/sample-template</a> - Download CSV Template</li>
            <li><a style="color:#38bdf8;" href="/api/audit/demo">/api/audit/demo</a> - Demo Asset Audit</li>
          </ul>
        </body>
      </html>
    `);
  });
}

// Start Server & Sync Feeds
app.listen(PORT, async () => {
  console.log(`\n======================================================`);
  console.log(`  THREAT-RADAR // CYBER INTELLIGENCE PLATFORM`);
  console.log(`  Server listening on: http://localhost:${PORT}`);
  console.log(`======================================================\n`);

  // Initialize live feeds in background
  try {
    await cisaService.initialize();
    await gitHubAdvisoryService.fetchAdvisories();
    await ipThreatService.initialize();
  } catch (err: any) {
    console.warn(`[Startup Feeds] Warning during feed init: ${err.message}`);
  }
});

// Process signal handling
process.on('SIGINT', () => {
  console.log('\n[ThreatRadar] Gracefully shutting down...');
  process.exit(0);
});

export default app;
