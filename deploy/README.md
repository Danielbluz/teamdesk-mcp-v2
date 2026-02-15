# TeamDesk MCP Server - SSE Remote Deployment

Multi-user SSE server with API key authentication, rate limiting, and caching.

For single-user local use, see the main [README](../README.md).

## Architecture

```
Claude Desktop/Code  ──(SSE)──>  server_sse.py  ──(REST)──>  TeamDesk API
                                      │
                                 API-Keys table
                                 (per-user tokens)
```

Each user authenticates with an API key (sent via `X-API-Key` header).
The server maps each API key to a per-user TeamDesk token, so authorization
is handled natively by TeamDesk roles.

## Quick Start

1. **Create the API-Keys table** in TeamDesk with columns:
   - `Key` (Text, Unique) - The API key string
   - `Token` (Text) - User's TeamDesk REST API token
   - `Ativo` (Text) - "Sim" to enable
   - `Nome` (Text) - User name for logging
   - `Ultimo_Uso` (DateTime) - Auto-updated on each request

2. **Configure** `.env` from `.env.example`

3. **Run with Docker:**
   ```bash
   cd deploy/
   cp .env.example .env
   # Edit .env with your credentials
   docker compose up -d
   ```

4. **Or run directly:**
   ```bash
   cd deploy/
   pip install -r requirements.txt
   python server_sse.py
   ```

5. **Connect from Claude Desktop:**
   ```json
   {
     "mcpServers": {
       "teamdesk": {
         "url": "https://mcp.yourdomain.com/sse",
         "headers": {
           "X-API-Key": "your-api-key"
         }
       }
     }
   }
   ```

## Nginx + SSL

See `nginx.conf.example` for a reverse proxy configuration with SSE support.

```bash
sudo certbot --nginx -d mcp.yourdomain.com
```

## Endpoints

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/tools` | GET | No | List available tools |
| `/tools/call` | POST | X-API-Key | Execute a tool |
| `/sse` | GET | X-API-Key | MCP SSE connection |
