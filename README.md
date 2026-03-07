<p align="center">
  <img src="https://img.shields.io/badge/PhishWatch-v2.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/CertStream-Real--time-orange?style=for-the-badge" alt="CertStream">
  <img src="https://img.shields.io/badge/OpenSquat-NRD-purple?style=for-the-badge" alt="OpenSquat">
</p>

<h1 align="center">🛡️ PhishWatch</h1>
<h3 align="center">Real-time Phishing Detection Platform</h3>

<p align="center">
  Monitor, detect, and analyze phishing domains as they appear.<br>
  Combines <strong>CertStream</strong> certificate transparency monitoring with <strong>OpenSquat</strong><br>
  domain squatting detection for comprehensive, real-time phishing defense.
</p>

<p align="center">
  <a href="https://siteq8.github.io/PhishWatch/">🔴 Live Demo</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-api-reference">API Docs</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 📸 Screenshots

### Dashboard — Live Detection Feed

![PhishWatch Dashboard](screenshots/dashboard-main.png)

> Real-time phishing detection feed with brand impersonation tags, typosquatting detection, risk scoring, and filtered views. Monitors 70+ brands across tech, finance, crypto, e-commerce, and social media.

### Live Monitoring with Alerts

![PhishWatch Live](screenshots/dashboard-live.png)

> Active monitoring with toast alerts for critical threats. Stats update in real-time via WebSocket connections.

---

## ✨ Features

### 🔍 Real-time Detection
- **CertStream Integration** — Monitor SSL/TLS certificates as they're issued globally in real-time
- **OpenSquat Integration** — Detect domain squatting and typosquatting from newly registered domains
- **WebSocket Dashboard** — Live updates without page refresh, instant notifications

### 🧠 Intelligent Analysis
- **Brand Similarity Detection** — Identify domains impersonating 70+ known brands (PayPal, Microsoft, Google, Amazon, Chase, Coinbase, MetaMask, FedEx, and more)
- **Typosquatting Detection** — Character substitution (g00gle), omission (gogle), and addition (googles) patterns
- **Homograph/IDN Detection** — Catch Cyrillic, Greek, and other Unicode lookalike attacks
- **Shannon Entropy Analysis** — Detect algorithmically generated domains (DGA)
- **Multi-factor Risk Scoring** — 9-factor weighted scoring system (0-100 scale)

### 📊 Professional Dashboard
- **4 Views** — Dashboard, All Detections, Threat Intelligence, Domain Analysis
- **Risk Filtering** — Filter by Critical/High/Medium, by source, search
- **Interactive Charts** — Risk distribution and detection timeline
- **Manual Analysis** — Analyze any domain on-demand via the UI
- **CSV/JSON Export** — Export detection data for SIEM integration
- **Toast Alerts** — Real-time notifications for high-severity detections

### 🔧 Platform
- **REST API** — Full API for integration with security tools and automation
- **CLI Tool** — Command-line interface for scripting and CI/CD
- **Python Package** — `pip install` ready with `pyproject.toml`
- **Docker Ready** — Dockerfile and Docker Compose included
- **CI/CD** — GitHub Actions workflow for testing across Python 3.9-3.12
- **20+ Unit Tests** — Comprehensive test coverage

### 🏭 Advanced: ICS/IoT/OT Module
- Detects phishing targeting industrial control systems (30+ vendors: Siemens, Schneider, Rockwell, Honeywell, ABB...)
- Industrial protocol keyword matching (Modbus, DNP3, OPC UA, BACnet, PROFINET...)
- MITRE ATT&CK for ICS technique mapping
- Automatic ICS-aware risk multiplier for elevated threat scoring

---

## 🚀 Quick Start

### Option 1: pip install

```bash
git clone https://github.com/SiteQ8/PhishWatch.git
cd PhishWatch
pip install -e .
phishwatch serve
```

Open http://localhost:5000 and click **Start Monitoring**.

### Option 2: Docker

```bash
git clone https://github.com/SiteQ8/PhishWatch.git
cd PhishWatch
docker compose up -d
```

### Option 3: Manual

```bash
git clone https://github.com/SiteQ8/PhishWatch.git
cd PhishWatch
pip install -r requirements.txt
python -m phishwatch serve
```

---

## 💻 CLI Usage

### Analyze a domain

```bash
# Human-readable output
phishwatch analyze paypal-login-secure.tk

# JSON output
phishwatch analyze paypal-login-secure.tk --json
```

**Example output:**
```
============================================================
  PhishWatch Domain Analysis
============================================================
  Domain:       paypal-login-secure.tk
  Risk Score:   94/100
  Threat Level: CRITICAL
  Summary:      CRITICAL (94/100): paypal-login-secure.tk — probable target: paypal

  Recommendations:
    • IMMEDIATE: Block domain across all network segments including OT
    • Add to SIEM and firewall deny-lists
    • Alert SOC and OT security teams
    • Check for similar domains (typosquatting variants)
    • Investigate brand impersonation — consider takedown
============================================================
```

### Start the dashboard

```bash
phishwatch serve --port 8080 --debug
```

---

## 📡 API Reference

All endpoints are under `/api/v2/`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v2/status` | Platform status and stats |
| `GET` | `/api/v2/detections` | List detections (filterable) |
| `POST` | `/api/v2/start` | Start monitoring |
| `POST` | `/api/v2/stop` | Stop monitoring |
| `POST` | `/api/v2/analyze` | Analyze a single domain |
| `GET/POST/DELETE` | `/api/v2/keywords` | Manage watchlist keywords |
| `GET` | `/api/v2/export?format=csv` | Export detections (CSV/JSON) |

### Query Parameters for `/api/v2/detections`

| Param | Values | Description |
|-------|--------|-------------|
| `risk` | `all`, `critical`, `high`, `medium`, `low` | Filter by risk level |
| `source` | `all`, `certstream`, `opensquat` | Filter by detection source |
| `ics_only` | `true`, `false` | Show only ICS/OT targeted |
| `limit` | `1-1000` | Max results |

### Analyze a domain via API

```bash
curl -X POST http://localhost:5000/api/v2/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "g00gle-account-security.top"}'
```

---

## 🏗️ Architecture

```
PhishWatch/
├── phishwatch/
│   ├── __init__.py              # Package metadata
│   ├── __main__.py              # python -m phishwatch
│   ├── app.py                   # Flask + SocketIO application
│   ├── cli.py                   # CLI entry point
│   ├── config.py                # Configuration & brand watchlists
│   ├── core/
│   │   ├── domain_analyzer.py   # Domain analysis (similarity, entropy, homograph)
│   │   ├── threat_classifier.py # Multi-factor risk scoring
│   │   ├── ics_iot_detector.py  # ICS/IoT/OT detection module (advanced)
│   │   ├── certstream_monitor.py# Real-time certificate monitoring
│   │   └── opensquat_integration.py # Domain squatting detection
│   ├── templates/
│   │   └── dashboard.html       # Web dashboard
│   └── static/
│       ├── css/dashboard.css
│       └── js/dashboard.js
├── tests/                       # Test suite (20+ tests)
├── docs/index.html              # GitHub Pages live demo
├── screenshots/                 # Dashboard screenshots
├── Dockerfile                   # Production container
├── docker-compose.yml
├── pyproject.toml               # Python packaging
└── README.md
```

### Detection Pipeline

```
CertStream (WSS) ──┐
                    ├─▶ Domain Analyzer ─▶ Threat Classifier ─▶ Dashboard
OpenSquat (NRD) ───┘    · Brand similarity    · 9-factor scoring   · WebSocket
                        · Typosquatting        · ICS/OT multiplier  · Real-time
                        · Homograph detect     · Classification     · Alerts
                        · Entropy / DGA        · Recommendations    · Export
```

---

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v --cov=phishwatch
```

---

## 🐳 Docker Deployment

```bash
docker compose up -d
# Or manually:
docker build -t phishwatch .
docker run -p 5000:5000 -e SECRET_KEY=your-secret phishwatch
```

---

## ⚙️ Configuration

Environment variables or `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me` | Flask secret key |
| `LOG_LEVEL` | `INFO` | Logging level |
| `CERTSTREAM_URL` | `wss://certstream.calidog.io/` | CertStream endpoint |
| `OPENSQUAT_SCAN_INTERVAL` | `1800` | Seconds between scans |
| `MAX_DETECTIONS` | `5000` | Max stored detections |
| `CRITICAL_THRESHOLD` | `90` | Critical risk threshold |

---

## 🗺️ Roadmap

- [ ] STIX/TAXII export for threat intelligence sharing
- [ ] VirusTotal & URLScan.io integration
- [ ] Machine learning classifier for phishing confidence
- [ ] Email/Slack alerting for critical detections
- [ ] SQLite/PostgreSQL persistence
- [ ] Grafana dashboard integration
- [ ] YARA rule generation from detections
- [ ] Shodan integration for infrastructure analysis

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📝 License

MIT License — see [LICENSE](LICENSE).

---

## 👤 Author

**Ali AlEnezi** ([@SiteQ8](https://github.com/SiteQ8))

---

<p align="center">
  <strong>PhishWatch</strong> — Catching phishing domains before they catch you.
</p>
