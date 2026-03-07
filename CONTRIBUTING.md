# Contributing to PhishWatch

Thank you for your interest in contributing to PhishWatch!

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest tests/ -v`
5. Run linting: `ruff check phishwatch/`
6. Commit: `git commit -m "feat: description"`
7. Push and open a Pull Request

## Development Setup

```bash
git clone https://github.com/SiteQ8/PhishWatch.git
cd PhishWatch
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Code Style

- Follow PEP 8 (enforced by ruff)
- Type hints for all public functions
- Docstrings for all modules and classes
- Keep functions focused and testable

## Areas for Contribution

- Additional ICS/OT vendor keywords and detection patterns
- MITRE ATT&CK for ICS technique mapping
- New export formats (STIX/TAXII, OpenIOC)
- Dashboard UI improvements
- Documentation and examples
- Integration with threat intelligence feeds
