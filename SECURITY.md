# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT open a public issue**
2. Open a private security advisory on this GitHub repository
3. Include steps to reproduce and potential impact

I will acknowledge receipt within 48 hours and provide a fix timeline.

## Security Considerations

### API Tokens
- Never commit `.env` files or API tokens to version control
- Use environment variables for all credentials
- The `.gitignore` file excludes `.env`, `*.pem`, and `*.key` files

### SSE Remote Mode
- Always deploy behind TLS (HTTPS) via Nginx or similar reverse proxy
- Use API keys via the `X-API-Key` header only (not query parameters)
- Configure `MCP_CORS_ORIGINS` to restrict allowed origins (avoid `*` in production)
- Each user should have their own TeamDesk token with appropriate role permissions

### Input Validation
- Table names are URL-encoded (not stripped) to preserve accented characters
- Search text has single quotes escaped to prevent filter injection
- API keys are validated against a strict alphanumeric pattern
