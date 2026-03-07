# Changelog

## [2.0.0] — 2026-03-07

### Added
- **ICS/IoT/OT Detection Engine** — Specialized detection for phishing targeting industrial control systems, SCADA, HMI, PLCs, and OT vendor infrastructure
- ICS vendor impersonation detection (30+ vendors: Siemens, Schneider Electric, Rockwell, Honeywell, ABB, etc.)
- Industrial protocol keyword matching (Modbus, DNP3, OPC UA, BACnet, PROFINET, etc.)
- MITRE ATT&CK for ICS technique mapping
- Sector classification (Energy, Manufacturing, Oil & Gas, Building Automation, etc.)
- ICS-aware risk multiplier for elevated threat scoring
- Domain entropy analysis for DGA detection
- Homograph/IDN attack detection
- Manual domain analysis API endpoint
- CLI tool (`phishwatch serve`, `phishwatch analyze <domain>`)
- Proper Python packaging with `pyproject.toml` and pip installable
- Docker and Docker Compose support
- GitHub Actions CI pipeline
- Comprehensive test suite
- Modern dashboard with ICS/OT intelligence view
- Toast notifications for high-severity detections
- CSV and JSON export

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
