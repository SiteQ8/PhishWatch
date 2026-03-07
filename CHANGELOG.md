# Changelog

## [2.0.0] — 2026-03-07

### Added
- **Real-time Phishing Detection** — CertStream certificate transparency + OpenSquat NRD monitoring
- **Brand Impersonation Detection** — 70+ brands across tech, finance, crypto, e-commerce, social media, shipping
- **Typosquatting Analysis** — Character substitution, omission, and addition pattern detection
- **Homograph/IDN Attack Detection** — Cyrillic, Greek, and Unicode lookalike character detection
- **Shannon Entropy Analysis** — Detect algorithmically generated domains (DGA)
- **9-factor Weighted Risk Scoring** — Similarity, registration age, patterns, DNS, geography, TLD, entropy, homograph, ICS targeting
- **ICS/IoT/OT Module** — Advanced detection for phishing targeting industrial control systems (30+ vendors, 18+ protocols, MITRE ATT&CK mapping)
- **Modern Dashboard** — 4 views (Dashboard, Detections, Threat Intel, Analyze) with WebSocket real-time updates
- **CLI Tool** — `phishwatch serve` and `phishwatch analyze <domain>` commands
- **REST API v2** — Full API for integration with security tools
- **Python Package** — pip installable with `pyproject.toml`
- **Docker Support** — Dockerfile and Docker Compose
- **GitHub Actions CI** — Testing across Python 3.9-3.12
- **20+ Unit Tests** — Comprehensive test coverage
- **GitHub Pages Demo** — Interactive live demo
- **CSV/JSON Export** — Export detections for SIEM integration

### Changed
- Complete architecture rewrite from v1
- Modular package structure (`phishwatch.core.*`)
- Enhanced threat classifier with 9-factor weighted scoring
- Redesigned dashboard UI with dark industrial theme
- API v2 endpoints under `/api/v2/`

### Removed
- Legacy v1 monolithic structure

## [1.0.0] — 2025

- Initial release with CertStream and OpenSquat integration
- Basic phishing detection dashboard
