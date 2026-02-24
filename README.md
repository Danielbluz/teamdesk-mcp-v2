# TeamDesk MCP Server

MCP (Model Context Protocol) server for [TeamDesk](https://www.teamdesk.net/) databases. Connects **Claude Desktop**, **Claude Code**, or any MCP-compatible client to the TeamDesk REST API v2.

## Features

- **11 tools** covering all TeamDesk CRUD operations + search + document generation
- Works with **any TeamDesk database** — just provide your token and database ID
- Correct URL encoding for accented table/column names (Portuguese, Spanish, etc.)
- Timeout handling with automatic retry (55s timeout, 2 retries with backoff)
- Filter injection prevention via input sanitization
- Stderr logging for request timing and debugging

## Requirements

- **Python 3.10+**
- A **TeamDesk REST API token** (generate at: TeamDesk > Setup > Integration > REST API > Tokens)
- Your **TeamDesk Database ID** (visible in the TeamDesk URL: `teamdesk.net/secure/db/XXXXX`)

## Installation

### Option A: Automated Installer (Windows)

1. Download `install.bat`, `server.py`, and `requirements.txt` from this repo
2. Place them in the same folder
3. Run `install.bat`
4. Follow the prompts (it will ask for your token and database ID)
5. Restart Claude Desktop

### Option B: Automated Installer (Linux / Mac)

1. Clone and run:

```bash
git clone https://github.com/Danielbluz/teamdesk-mcp-v2.git
cd teamdesk-mcp-v2
bash install.sh
```

2. Follow the prompts
3. Restart Claude Desktop

### Option C: Manual Setup

```bash
git clone https://github.com/Danielbluz/teamdesk-mcp-v2.git
cd teamdesk-mcp-v2
pip install -r requirements.txt
```

Then add to your client config (see next section).

## Configuration

### Claude Desktop

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

## Security

- Tokens are read from environment variables, never hardcoded
- Filter injection prevented by escaping single quotes
- Table names are URL-encoded to preserve accented characters
- See [SECURITY.md](SECURITY.md) for responsible disclosure

## License

MIT
