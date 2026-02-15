# TeamDesk MCP Server

MCP (Model Context Protocol) server for [TeamDesk](https://www.teamdesk.net/) database integration. Connects Claude Desktop, Claude Code, or any MCP-compatible client to the TeamDesk REST API.

## Features

- **11 tools** covering all TeamDesk operations
- **FastMCP stdio** transport (local, single-user)
- **SSE remote** transport with API key auth, rate limiting, and caching (multi-user, in `deploy/`)
- Correct URL encoding for accented table/column names (Portuguese, etc.)
- Filter injection prevention via input sanitization
- Automated tests for all endpoints and security checks

## Quick Start (Local)

### 1. Install

```bash
git clone https://github.com/Danielbluz/teamdesk-mcp-v2.git
cd teamdesk-mcp-v2
pip install -r requirements.txt
```

Or use the installer:
- **Windows:** `install.bat`
- **Linux/Mac:** `bash install.sh`

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your TeamDesk credentials:
#   TEAMDESK_TOKEN=your_rest_api_token
#   TEAMDESK_DATABASE_ID=your_database_id
```

Get your token at: **TeamDesk > Setup > Integration > REST API > Tokens**

### 3. Add to Claude Desktop / Claude Code

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "teamdesk": {
      "command": "python",
      "args": ["/path/to/teamdesk-mcp-v2/server.py"],
      "env": {
        "TEAMDESK_TOKEN": "your_token",
        "TEAMDESK_DATABASE_ID": "your_database_id"
      }
    }
  }
}
```

## Tools

| Tool | Endpoint | Method | Description |
|------|----------|--------|-------------|
| `list_tables` | `describe.json` | GET | List all tables |
| `describe_table` | `{table}/describe.json` | GET | Table structure (columns, types) |
| `get_records` | `{table}/select.json` | GET | Query with filters, sort, pagination |
| `select_view` | `{table}/{view}/select.json` | GET | Query from a pre-configured View |
| `get_record` | `{table}/retrieve.json?id={id}` | GET | Single record by ID |
| `create_record` | `{table}/create.json` | POST | Create record (body: JSON array) |
| `update_record` | `{table}/update.json` | POST | Update record (body: array with `@row.id`) |
| `delete_record` | `{table}/delete.json?id={id}` | GET | Delete record (yes, GET) |
| `search_records` | `{table}/select.json?filter=Contains(...)` | GET | Full-text search |
| `upsert_records` | `{table}/upsert.json?match={col}` | POST | Insert/update (match column must be Unique) |
| `gerar_documento` | `{table}/{doc}/document?id={id}` | GET | Generate DOCX via Mail Merge |

### Filter examples

```
[Status] = 'Ativo'
[Potencia] > 1000
Contains([Nome], 'Solar')
[Data] >= '2026-01-01'
```

### Sort syntax

```
Column          -- ascending
Column//DESC    -- descending
```

## Remote Deployment (Multi-User)

For shared server deployment with API key authentication, see [`deploy/README.md`](deploy/README.md).

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## TeamDesk API Quirks

These are undocumented behaviors that this server handles correctly:

1. **DELETE uses GET** - `{table}/delete.json?id={id}` is a GET request
2. **UPDATE uses POST** - Not PUT. Body must include `@row.id`
3. **Body must be array** - All write operations require `[{...}]`, not `{...}`
4. **Upsert match column must be Unique** - Otherwise error 3106
5. **Document endpoint has no `.json`** - `/document?id=X`, not `/document.json?id=X`
6. **Sort uses `//`** - `Column//DESC`, not `-Column`
7. **Accented names are valid** - `Geração`, `Irradiação` - must be URL-encoded, not stripped
8. **`Contains()` for search** - No LIKE operator. Use `Contains([field], 'value')` (case-insensitive)
9. **Retrieve single record** - Use `retrieve.json?id=X`, not `{id}.json`

## Security

- Tokens are read from environment variables, never hardcoded
- Filter injection prevented by escaping single quotes in search text
- Table names are URL-encoded (not character-stripped) to preserve accented names
- See [SECURITY.md](SECURITY.md) for responsible disclosure and best practices

## Acknowledgments

Special thanks to **L.C. Parker** for the thorough security audit and endpoint documentation that significantly improved this project (CRMdesk #2139).

## License

MIT
