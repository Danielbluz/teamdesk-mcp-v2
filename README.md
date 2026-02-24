# TeamDesk MCP Server

MCP (Model Context Protocol) server for [TeamDesk](https://www.teamdesk.net/) databases. Connects **Claude** (web, Desktop, and mobile), **Claude Code**, or any MCP-compatible client to the TeamDesk REST API v2.

## Features

- **11 tools** covering all TeamDesk CRUD operations + search + document generation
- Works with **any TeamDesk database** — just provide your token and database ID
- **Two deployment modes:**
  - **Local** (`server.py`) — runs on user's machine via stdio
  - **Remote** (`deploy/server_sse.py`) — multi-user server with OAuth 2.0, Streamable HTTP, rate limiting, and caching
- Correct URL encoding for accented table/column names (Portuguese, Spanish, etc.)
- Timeout handling with automatic retry (55s timeout, 2 retries with backoff)
- Filter injection prevention via input sanitization
- Stderr logging for request timing and debugging

## Requirements

- **Python 3.10+**
- A **TeamDesk REST API token** (generate at: TeamDesk > Setup > Integration > REST API > Tokens)
- Your **TeamDesk Database ID** (visible in the TeamDesk URL: `teamdesk.net/secure/db/XXXXX`)

## Installation

### Option 1: Remote Connector (Recommended)

**No local installation required.** Connect directly from claude.ai — works on web, Desktop, and mobile automatically.

> When you add a custom connector on claude.ai, it syncs to Claude Desktop and mobile automatically. One setup covers all platforms.

1. Ask your admin to create an access key (see [Remote Deployment](#remote-deployment))
2. Go to **claude.ai** > **Settings** > **Integrations** > **Add Custom Connector**
3. Enter a name (e.g., `TeamDesk`) and the server URL: `https://your-server.com/m/{your_key}/sse`
4. Click **Configure** > approve access
5. Done — works on web, Desktop, and mobile

### Option 2: Local Installer (Windows)

1. Download `install.bat`, `server.py`, and `requirements.txt` from this repo
2. Place them in the same folder
3. Run `install.bat`
4. Follow the prompts (it will ask for your token and database ID)
5. Restart Claude Desktop

### Option 3: Local Installer (Linux / Mac)

1. Clone and run:

```bash
git clone https://github.com/Danielbluz/teamdesk-mcp-v2.git
cd teamdesk-mcp-v2
bash install.sh
```

2. Follow the prompts
3. Restart Claude Desktop

### Option 4: Manual Setup

```bash
git clone https://github.com/Danielbluz/teamdesk-mcp-v2.git
cd teamdesk-mcp-v2
pip install -r requirements.txt
```

Then add to your client config (see next section).

## Configuration

### Claude Desktop (local mode)

Edit `claude_desktop_config.json`:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "teamdesk": {
      "command": "python",
      "args": ["C:\\path\\to\\server.py"],
      "env": {
        "TEAMDESK_API_TOKEN": "your_token_here",
        "TEAMDESK_DATABASE_ID": "your_database_id"
      }
    }
  }
}
```

### Claude Code

Add to `.claude/.mcp.json` in your project or `~/.claude/.mcp.json` globally:

```json
{
  "mcpServers": {
    "teamdesk": {
      "command": "python",
      "args": ["C:\\path\\to\\server.py"],
      "env": {
        "TEAMDESK_API_TOKEN": "your_token_here",
        "TEAMDESK_DATABASE_ID": "your_database_id"
      }
    }
  }
}
```

### Alternative: `.env` file

Instead of setting env vars in the config, you can create a `.env` file next to `server.py`:

```bash
cp .env.example .env
# Edit .env with your credentials
```

## Tools

| Tool | Description |
|------|-------------|
| `list_tables` | List all tables in the database |
| `describe_table` | Get table structure (columns, types, properties) |
| `get_records` | Query records with filters, sort, and pagination |
| `get_record` | Retrieve a single record by ID |
| `select_view` | Query records from a pre-configured View |
| `create_record` | Create a new record |
| `update_record` | Update an existing record by ID |
| `delete_record` | Delete a record by ID |
| `search_records` | Full-text search across text columns (auto-detected) |
| `upsert_records` | Insert or update records (match column must be Unique) |
| `gerar_documento` | Generate a DOCX from a TeamDesk Documents template |

### Filter Examples

```
[Status] = 'Ativo'
[Amount] > 1000
Contains([Name], 'Solar')
[Date] >= ToDate('2026-01-01')
```

### Sort Syntax

```
Column          -- ascending (default)
Column//DESC    -- descending
```

## TeamDesk API Quirks

These are undocumented behaviors that this server handles correctly:

| Quirk | Detail |
|-------|--------|
| DELETE uses GET | `{table}/delete.json?id={id}` is a GET request |
| UPDATE uses POST | Not PUT. Body must include `@row.id` |
| Body must be array | All write operations require `[{...}]`, not `{...}` |
| Upsert match must be Unique | Match column must be marked Unique in table setup, otherwise error 3106 |
| Document endpoint has no `.json` | Use `/document?id=X`, not `/document.json?id=X` |
| Sort uses `//` | `Column//DESC`, not `-Column` or `Column DESC` |
| Accented names are valid | `Geração`, `Irradiação` — must be URL-encoded, not stripped |
| No LIKE operator | Use `Contains([field], 'value')` (case-insensitive) |
| Date literals use `#` | `[Date] >= #2026-01-01#` or `ToDate('2026-01-01')` |
| Retrieve by ID | Use `retrieve.json?id=X`, not `{id}.json` |

## Troubleshooting

### MCP not appearing in Claude Desktop
- Make sure you restarted Claude Desktop completely (check system tray)
- Verify `python` is in your PATH: `python --version`
- Check the config JSON syntax (no trailing commas)

### Slow responses
- TeamDesk servers can be slow during US business hours (15:00–18:00 UTC)
- The server retries automatically on timeout (up to 2 times)
- Check logs: Claude Desktop > Ctrl+Shift+I > Console > filter `[TeamDesk MCP]`

### Token issues
- Generate a new token at: TeamDesk > Setup > Integration > REST API > Tokens
- The token should be a 32-character hex string
- Both `TEAMDESK_API_TOKEN` and `TEAMDESK_TOKEN` (legacy) are accepted

## Remote Deployment

The `deploy/` folder contains `server_sse.py` — a multi-user remote MCP server designed for deployment on a VPS behind Nginx/TLS. It supports:

- **OAuth 2.0** with auto-approve (PKCE S256) — required by claude.ai custom connectors
- **Streamable HTTP** transport (MCP SDK 1.26.0+) — the protocol claude.ai uses
- **SSE** transport — for Claude Desktop local config via URL
- **Multi-user authentication** via API keys stored in a TeamDesk table
- **Rate limiting** and **response caching**
- **Per-user tokens** — each user's API key maps to their own TeamDesk token

### How it works

1. Admin creates a record in the `Acesso` table (TeamDesk) with:
   - `Chave_MCP`: unique key for the user (e.g., `john_company_2026`)
   - `Token`: the user's TeamDesk API token
   - `Ativo_MCP`: `Sim` (to enable access)

2. Each user gets a personal endpoint: `https://your-server.com/m/{chave}/sse`

3. The server validates the key, retrieves the user's token, and proxies all MCP tool calls to the TeamDesk API using that token.

### OAuth 2.0 endpoints

claude.ai requires these OAuth endpoints for custom connectors:

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/oauth-protected-resource` | RFC 9728 — resource metadata |
| `/.well-known/oauth-authorization-server` | RFC 8414 — auth server metadata |
| `/register` | RFC 7591 — dynamic client registration |
| `/authorize` | Authorization endpoint (auto-approve) |
| `/token` | Token exchange (PKCE S256 verification) |

### Technical notes

- claude.ai uses **POST** (Streamable HTTP), not GET (SSE) — the server handles both
- The server injects the `Accept: application/json, text/event-stream` header if missing (claude.ai sometimes omits it, causing 406 from MCP SDK)
- Sessions are **stateful** (`stateless=False`) — required for persistent `Mcp-Session-Id`
- Configure via environment variables (see `deploy/docker-compose.yml`)

### Docker deployment

```bash
cd deploy
cp .env.example .env
# Edit .env with your TEAMDESK_DATABASE_ID, TEAMDESK_MASTER_TOKEN, MCP_PUBLIC_URL
docker compose up -d
```

### Key discovery: web = Desktop = mobile

When a user configures a custom connector on **claude.ai** (web), it automatically becomes available on **Claude Desktop** and **Claude mobile** — no separate configuration needed. The connector is linked to the user's Anthropic **account**, not to a specific app.

This means: **one setup on the web covers all platforms.**

## Security

- Tokens are read from environment variables, never hardcoded
- Filter injection prevented by escaping single quotes
- Table names are URL-encoded to preserve accented characters
- API keys validated against TeamDesk table (not hardcoded)
- OAuth auto-approve uses PKCE S256 for security
- Rate limiting prevents abuse (configurable per-minute limit)
- See [SECURITY.md](SECURITY.md) for responsible disclosure

## License

MIT
