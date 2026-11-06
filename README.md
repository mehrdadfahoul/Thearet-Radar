# ThreatRadar // Enterprise Standalone Cyber Threat Intelligence & Vulnerability Platform

> **A modern, high-performance, containerized Cyber Threat Intelligence (CTI), Vulnerability Radar, and Threat Hunting platform built with TypeScript, React 18, Vite, Tailwind CSS, and Node.js Express.**

[![Node.js](https://img.shields.io/badge/Node.js-v22-green.svg)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-18-blue.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## 🛰 Overview

**ThreatRadar** is a completely self-contained, standalone Cyber Threat Intelligence platform. It requires **no external agents, no server auto-monitoring, and no commercial API keys**. It aggregates real-time data from 100% free and open national/global threat repositories:

1. **CISA KEV Catalog (Known Exploited Vulnerabilities):**
   - Automatically synchronizes on startup and re-syncs every 6 hours in the background.
   - High-speed in-memory indexing of 1,740+ actively exploited zero-days and ransomware targets.
2. **FIRST.org EPSS (Exploit Prediction Scoring System):**
   - Integrates predictive probability scores (0% to 100%) indicating how likely a CVE is to be exploited in the wild over the next 30 days.
3. **GitHub Global Security Advisories Stream:**
   - Real-time stream of security advisories cached for 10 minutes to deliver breaking 24/7 threat news.
4. **NIST NVD API 2.0 (National Vulnerability Database):**
   - **Smart Tail Fetching:** Solves NVD's chronological ascending order by querying the count first, then calculating `startIndex = Math.max(0, totalResults - limit)` to fetch the newest 2025–2026 CVEs first.
5. **Abuse.ch Feodo Tracker & Blocklist.de (Malicious IP & C2 Radar):**
   - Automatically synchronizes live botnet C2 servers, ransomware infrastructure, and distributed brute-force nodes globally.
6. **VirusTotal-Style File Hash & URL Threat Hunter:**
   - Instant in-memory MD5, SHA-1, SHA-256 cryptographic hashing correlated against Abuse.ch MalwareBazaar and URLhaus phishing/malware distribution feeds.

---

## ⚡ Core Architecture

```
                       +-----------------------------------+
                       |    Unified Frontend (React 18)    |
                       |    Dark Cyber-Ops Design System   |
                       |    Vite + Tailwind CSS + Lucide   |
                       +-----------------+-----------------+
                                         |
                                (HTTP / Port 4000)
                                         |
                       +-----------------v-----------------+
                       |     Backend Engine (Express/TS)   |
                       |         ThreatRadar Core          |
                       +--------+--------+--------+--------+
                                |        |        |
        +-----------------------+        |        +-----------------------+
        |                                |                                |
+-------v---------+             +--------v--------+             +---------v-------+
|  CISA KEV Feed  |             |  FIRST.org EPSS |             |   NIST NVD 2.0  |
| 6-Hour Resync   |             | Exploit Predict |             | Smart Tail Fetch|
| 1,748+ Zero-Days|             | Live 30-Day %   |             | Newest CVEs 1st |
+-----------------+             +-----------------+             +-----------------+
        |                                |                                |
+-------v---------+             +--------v--------+             +---------v-------+
| Feodo C2 / IPs  |             | MalwareBazaar   |             | Teams & SMTP    |
| Botnets & Nodes |             | & URLhaus Feeds |             | Webhook Alerts  |
+-----------------+             +-----------------+             +-----------------+
```

---

## 🛡️ Functional Modules

### 1. Live Threat News & Zero-Days (Live Newsroom)
- **Breaking Threats Ticker:** Animated top marquee banner featuring the newest active zero-days added in the wild.
- **Breaking News Feed Cards:**
  - Active Zero-Day in the Wild glowing badge.
  - Ransomware target campaign tags (e.g. *Volt Typhoon*, *LockBit*, *BlackCat*).
  - CVSS 3.1 severity gauges (`CRITICAL 9.8`, `HIGH 7.5`, etc.).
  - **FIRST.org EPSS Exploit Probability Pill** (e.g. `EPSS 94.2%`).
  - Humanized publication timestamps ("Today", "Yesterday", "2 days ago").
  - Affected Vendor & Product badges.
  - Emerald mitigation boxes with required actions and patching instructions.
  - Direct links to official CISA bulletins and vendor advisories.
- **Filters:** All News, Active Zero-Days, Critical (9.0+), and Ransomware Targets.

### 2. CVE Encyclopedia & Software Search (Dictionary)
- **Smart Tail Fetching:** Queries NIST NVD 2.0 ascending database from the tail so recent 2025/2026 CVEs display first.
- **Live Search Bar:** Search any software name (*Telegram*, *Nginx*, *OpenSSH*, *Fortinet*, *Windows*, *Cisco*...) or exact CVE ID (`CVE-2024-6387`).
- **Popular Target Quick Pills:** Instant one-click queries for 10 common software targets.
- **Vulnerability Cards:** Full CVSS breakdown, EPSS probability, attack vectors, CISA KEV due dates, remediation steps, and direct NVD links.
- **Filters:** All Results, Recent (2025–2026), Zero-Days (CISA KEV), and Critical (9.0+).

### 3. Inventory, Nmap & Nessus Auditor (Asset Scanner)
- **Multi-Format Ingestion:** Supports `.xlsx`, `.xls`, `.csv`, **Nmap XML (`.xml`)**, and **Nessus (`.nessus` XML or `.csv`)**.
- **Automated Service & Port Mapping:** Automatically extracts hosts, open ports, service banners, and software versions.
- **Nessus Vulnerability Prioritization:** Cross-references thousands of Nessus findings against CISA KEV so security teams can immediately patch vulnerabilities that are actively being weaponized today.
- **Sample Template Download:** Download ready-to-use CSV template directly via button or `/api/cve/sample-template`.
- **Load Demo Inventory:** Test the auditor with a single click using pre-configured enterprise assets.
- **Inspection Drawer:** Click "Inspect" on any asset to view all matching CVE records, attack vectors, EPSS scores, and specific patching actions.

### 4. IOC & Threat Hunter (Malicious IP, File & URL Radar)
- **Global Malicious IP Check:** Query any IPv4 address against active botnet C2s (QakBot, Emotet, Pikabot, Cobalt Strike) and brute-force scanners.
- **Bulk Firewall / Server Log Correlator:** Paste raw Nginx access logs, auth.log, or firewall connection dumps. ThreatRadar extracts all IPs and highlights infected or compromised connections.
- **VirusTotal-Style File Hash Scanner:** Upload suspicious files to compute MD5, SHA-1, and SHA-256 hashes in-memory and query global malware repositories (MalwareBazaar).
- **Phishing & Malicious URL Radar:** Inspect suspicious URLs and staging links against Abuse.ch URLhaus malware distribution feeds.

### 5. Enterprise Alerts (Microsoft Teams & SMTP Email)
- **Microsoft Teams Integration:** Transmit rich Adaptive Cards with severity color-coding, CVE metadata, and remediation links via Incoming Webhook.
- **SMTP Email Dispatcher:** Native Node.js SMTP sender transmitting cyber-ops HTML bulletins to your security mailing list.
- **Automated Triggers:** Configurable triggers for newly added CISA zero-days and critical inventory audit discoveries.

---

## 🚀 Quickstart Guide

### Option A: Run via Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/threat-radar.git
cd Threat-Radar

# Start with Docker Compose
docker compose up -d --build

# Open the platform in your browser
# http://localhost:4000
```

### Option B: Run Locally (Node.js v20+)

```bash
# Install dependencies
npm run install:all

# Build frontend and backend
npm run build

# Start the full-stack server
node backend/dist/server.js

# Open in browser
# http://localhost:4000
```

### Development Mode (Hot Reload)

```bash
# In terminal 1: Start backend
npm run dev:backend

# In terminal 2: Start frontend Vite dev server (proxies to backend)
npm run dev:frontend
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health, uptime, and feed synchronization statistics |
| `GET` | `/api/news` | Merged threat news feed with EPSS exploit probabilities |
| `GET` | `/api/news/ticker` | Active zero-days list for the marquee ticker |
| `GET` | `/api/cve/search?q={query}` | Smart Tail CVE search across NVD 2.0 & CISA catalog |
| `GET` | `/api/cve/details/:cveId` | Detailed record for a specific CVE identifier |
| `GET` | `/api/cve/sample-template` | Download sample `.csv` software inventory template |
| `POST` | `/api/audit/upload` | Upload `.xlsx`, `.csv`, Nmap `.xml`, or Nessus `.nessus` for correlation |
| `GET` | `/api/audit/demo` | Execute audit on simulated enterprise production assets |
| `GET` | `/api/threat-intel/ip/check?ip={ip}` | Check IP reputation against Feodo Tracker & Blocklist.de |
| `POST` | `/api/threat-intel/ip/bulk-scan` | Correlate raw firewall/server logs for malicious IP connections |
| `POST` | `/api/threat-intel/scan-file` | Compute MD5/SHA-256 and query MalwareBazaar registry |
| `POST` | `/api/threat-intel/scan-url` | Scan URL against URLhaus malware distribution feeds |
| `GET` | `/api/alerts/config` | Get Microsoft Teams and SMTP email configuration |
| `POST` | `/api/alerts/config` | Update alert dispatcher settings |
| `POST` | `/api/alerts/test-teams` | Dispatch a test card to Microsoft Teams Incoming Webhook |
| `POST` | `/api/alerts/test-email` | Dispatch a test email bulletin |

---

## 🔒 Security & Privacy Notice
ThreatRadar is strictly an offline auditing and threat correlation engine. It performs **no active port scanning, no host probing, and does not install any agents**. Uploaded inventory files and suspicious binaries are processed in-memory and are never stored on disk.
