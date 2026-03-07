# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | ✅        |
| < 2.0   | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in PhishWatch, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: ali@alenezi.me with subject `[PhishWatch Security]`
3. Include: description, reproduction steps, potential impact
4. You will receive acknowledgment within 48 hours

## Security Best Practices

- Always change `SECRET_KEY` in production
- Run behind a reverse proxy (nginx/Caddy) with TLS
- Use Docker for isolated deployment
- Restrict network access to the dashboard
- Regularly update dependencies
