"""
TeamDesk MCP Server - SSE Remote (deploy version)
Multi-user MCP server with API key authentication, rate limiting, and caching.
Designed for deployment on a VPS behind Nginx/TLS.

Usage:
    python server_sse.py
    # or
    uvicorn deploy.server_sse:app --host 0.0.0.0 --port 8080
"""

import os
import sys
import json
import time
import asyncio
import base64
import contextvars
import hashlib
import logging
import re
import secrets
import urllib.parse
import uuid
from typing import Any, Optional
from collections import defaultdict
from datetime import datetime, timezone
from contextlib import asynccontextmanager

# Force UTF-8 for stdout/stderr
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("teamdesk-mcp")

import httpx
from dotenv import load_dotenv
from td_query_checker import check_filter, check_columns, check_table_name, broaden_filter
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Tool, TextContent, Resource, Prompt, PromptArgument, PromptMessage, GetPromptResult
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

load_dotenv()

# Context variables for mobile SSE auth (token injected in endpoint, read in handle_call_tool)
current_user_token: contextvars.ContextVar[str] = contextvars.ContextVar("current_user_token")
current_user_key: contextvars.ContextVar[str] = contextvars.ContextVar("current_user_key")

# Configuration
TEAMDESK_DATABASE_ID = os.getenv("TEAMDESK_DATABASE_ID", "")
TEAMDESK_MASTER_TOKEN = os.getenv("TEAMDESK_MASTER_TOKEN", "")
TEAMDESK_API_KEYS_TABLE = os.getenv("TEAMDESK_API_KEYS_TABLE", "Acesso")
TEAMDESK_COL_KEY = os.getenv("TEAMDESK_COL_KEY", "Chave_MCP")
TEAMDESK_COL_TOKEN = os.getenv("TEAMDESK_COL_TOKEN", "Token")
TEAMDESK_COL_ACTIVE = os.getenv("TEAMDESK_COL_ACTIVE", "Ativo_MCP")
TEAMDESK_COL_NAME = os.getenv("TEAMDESK_COL_NAME", "Nome")
TEAMDESK_COL_LAST_USE = os.getenv("TEAMDESK_COL_LAST_USE", "Ultimo_Uso")
MCP_RATE_LIMIT = int(os.getenv("MCP_RATE_LIMIT", "100"))
MCP_CACHE_TTL = int(os.getenv("MCP_CACHE_TTL", "300"))
MCP_API_KEY_CACHE_TTL = int(os.getenv("MCP_API_KEY_CACHE_TTL", "60"))
MCP_CORS_ORIGINS = os.getenv("MCP_CORS_ORIGINS", "").split(",")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8080"))
MCP_MAX_PAYLOAD_SIZE = int(os.getenv("MCP_MAX_PAYLOAD_SIZE", "1048576"))
MCP_PUBLIC_URL = os.getenv("MCP_PUBLIC_URL", "https://mcp.forgreen.com.br")

TEAMDESK_API_BASE = "https://www.teamdesk.net/secure/api/v2"

# API key validation regex: alphanumeric, underscores, hyphens, dots (8-128 chars)
_API_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.\*]{8,128}$")


def validate_api_key_format(api_key: str) -> bool:
    """Validate API key contains only safe characters and is 8-128 chars."""
    return bool(_API_KEY_PATTERN.match(api_key))


# ============================================================================
# RATE LIMITER
# ============================================================================


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_id: str) -> tuple[bool, int]:
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self.requests[client_id] = [
                t for t in self.requests[client_id] if t > cutoff
            ]
            count = len(self.requests[client_id])
            if count >= self.max_requests:
                return False, 0
            self.requests[client_id].append(now)
            return True, self.max_requests - count - 1

    async def cleanup(self):
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            empty = []
            for cid, ts in self.requests.items():
                self.requests[cid] = [t for t in ts if t > cutoff]
                if not self.requests[cid]:
                    empty.append(cid)
            for cid in empty:
                del self.requests[cid]


# ============================================================================
# CACHE
# ============================================================================


class CacheEntry:
    def __init__(self, value: Any, ttl: int):
        self.value = value
        self.expires_at = time.time() + ttl


class TTLCache:
    def __init__(self, default_ttl: int = 300):
        self.default_ttl = default_ttl
        self.cache: dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    def _key(self, token: str, op: str, params: dict) -> str:
        raw = f"{token}:{op}:{json.dumps(params, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()

    async def get(self, token: str, op: str, params: dict) -> tuple[Any, bool]:
        async with self._lock:
            key = self._key(token, op, params)
            entry = self.cache.get(key)
            if entry is None:
                return None, False
            if time.time() > entry.expires_at:
                del self.cache[key]
                return None, False
            return entry.value, True

    async def set(self, token: str, op: str, params: dict, value: Any, ttl: int = None):
        async with self._lock:
            key = self._key(token, op, params)
            self.cache[key] = CacheEntry(value, ttl or self.default_ttl)

    async def cleanup(self):
        async with self._lock:
            now = time.time()
            expired = [k for k, v in self.cache.items() if now > v.expires_at]
            for k in expired:
                del self.cache[k]


# ============================================================================
# API KEY VALIDATOR
# ============================================================================


class ApiKeyValidationResult:
    def __init__(self, valid: bool, token: str = None, user_name: str = None,
                 api_key: str = None, error: str = None):
        self.valid = valid
        self.token = token
        self.user_name = user_name
        self.api_key = api_key
        self.error = error


class ApiKeyValidator:

    def __init__(self, cache_ttl: int = 60):
        self.cache: dict[str, tuple[ApiKeyValidationResult, float]] = {}
        self.cache_ttl = cache_ttl
        self._lock = asyncio.Lock()

    async def validate(self, api_key: str, http_client: "TeamDeskClient") -> ApiKeyValidationResult:
        # Input validation
        if not api_key or not validate_api_key_format(api_key):
            return ApiKeyValidationResult(valid=False, error="Invalid API key format")

        # Check cache
        async with self._lock:
            if api_key in self.cache:
                result, exp = self.cache[api_key]
                if time.time() < exp:
                    return result
                del self.cache[api_key]

        if not TEAMDESK_MASTER_TOKEN:
            return ApiKeyValidationResult(
                valid=False, error="Server not configured: TEAMDESK_MASTER_TOKEN missing"
            )

        # Escape single quotes to prevent filter injection
        safe_key = api_key.replace("'", "''")
        response = await http_client.request(
            method="GET",
            token=TEAMDESK_MASTER_TOKEN,
            endpoint=f"{urllib.parse.quote(TEAMDESK_API_KEYS_TABLE, safe='')}/select.json",
            params={
                "filter": f"[{TEAMDESK_COL_KEY}]='{safe_key}'",
                "column": [TEAMDESK_COL_KEY, TEAMDESK_COL_TOKEN, TEAMDESK_COL_ACTIVE, TEAMDESK_COL_NAME],
            },
        )

        if "error" in response:
            return ApiKeyValidationResult(
                valid=False, error=f"Validation error: {response['error']}"
            )

        records = response if isinstance(response, list) else response.get("data", [])
        if not records:
            result = ApiKeyValidationResult(valid=False, error="API key not found")
            async with self._lock:
                self.cache[api_key] = (result, time.time() + 10)
            return result

        record = records[0]
        ativo = record.get(TEAMDESK_COL_ACTIVE, "")
        if ativo not in ("Sim", "Yes", True, "true", "1", 1):
            result = ApiKeyValidationResult(valid=False, error="API key disabled")
            async with self._lock:
                self.cache[api_key] = (result, time.time() + 10)
            return result

        user_token = record.get(TEAMDESK_COL_TOKEN, "") or TEAMDESK_MASTER_TOKEN
        result = ApiKeyValidationResult(
            valid=True,
            token=user_token,
            user_name=record.get(TEAMDESK_COL_NAME, ""),
            api_key=api_key,
        )
        async with self._lock:
            self.cache[api_key] = (result, time.time() + self.cache_ttl)
        return result

    async def update_last_use(self, api_key: str, http_client: "TeamDeskClient"):
        if not api_key or not TEAMDESK_MASTER_TOKEN:
            return
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            table = urllib.parse.quote(TEAMDESK_API_KEYS_TABLE, safe="")
            match = urllib.parse.quote(TEAMDESK_COL_KEY, safe="")
            await http_client.request(
                method="POST",
                token=TEAMDESK_MASTER_TOKEN,
                endpoint=f"{table}/upsert.json?match={match}",
                json_data=[{TEAMDESK_COL_KEY: api_key, TEAMDESK_COL_LAST_USE: now}],
                retries=1,
            )
        except Exception:
            pass

    async def cleanup(self):
        async with self._lock:
            now = time.time()
            expired = [k for k, (_, exp) in self.cache.items() if now > exp]
            for k in expired:
                del self.cache[k]


# ============================================================================
# HTTP CLIENT
# ============================================================================


class TeamDeskClient:
    def __init__(self):
        self.client: Optional[httpx.AsyncClient] = None

    async def start(self):
        if self.client is None:
            self.client = httpx.AsyncClient(
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
                timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0),
            )

    async def stop(self):
        if self.client:
            await self.client.aclose()
            self.client = None

    async def request(self, method: str, token: str, endpoint: str,
                      params: dict = None, json_data: Any = None, retries: int = 3) -> dict:
        if not self.client:
            await self.start()

        url = f"{TEAMDESK_API_BASE}/{TEAMDESK_DATABASE_ID}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        last_error = None
        for attempt in range(retries):
            try:
                resp = await self.client.request(
                    method=method, url=url, headers=headers,
                    params=params, json=json_data,
                )
                if resp.status_code == 401:
                    return {"error": "Invalid or expired token", "status": 401}
                if resp.status_code == 403:
                    return {"error": "Permission denied", "status": 403}
                if resp.status_code == 404:
                    return {"error": "Resource not found", "status": 404}
                if resp.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"Server error: {resp.status_code}",
                        request=resp.request, response=resp,
                    )
                if resp.status_code >= 400:
                    try:
                        return {"error": resp.json(), "status": resp.status_code}
                    except Exception:
                        return {"error": resp.text, "status": resp.status_code}
                try:
                    return resp.json()
                except Exception:
                    return {"data": resp.text}
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPStatusError) as e:
                last_error = e
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
                continue
        return {"error": f"Failed after {retries} attempts: {last_error}", "status": 503}


# ============================================================================
# INPUT VALIDATION
# ============================================================================


def sanitize_table_name(name: str) -> str:
    """URL-encode table name to handle accented characters safely."""
    return urllib.parse.quote(name, safe="")


def validate_required(params: dict, required: list[str]) -> Optional[str]:
    missing = [p for p in required if not params.get(p)]
    if missing:
        return f"Missing required parameters: {', '.join(missing)}"
    return None


def sanitize_search_text(text: str) -> str:
    """Escape single quotes to prevent filter injection."""
    return text.replace("'", "''")


# ============================================================================
# MCP TOOLS - All endpoints corrected per TeamDesk API v2 docs
# ============================================================================

TOOLS = [
    Tool(
        name="list_tables",
        description="List all tables in the TeamDesk database",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="describe_table",
        description="Describe a table's structure (columns, types)",
        inputSchema={
            "type": "object",
            "properties": {"table": {"type": "string", "description": "Table name"}},
            "required": ["table"],
        },
    ),
    Tool(
        name="get_records",
        description="Query records from a table with optional filters",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "filter": {"type": "string", "description": "TeamDesk filter (e.g. [Campo]='valor')"},
                "columns": {"type": "array", "items": {"type": "string"}, "description": "Columns to return"},
                "top": {"type": "integer", "description": "Max records (default: 100)"},
                "skip": {"type": "integer", "description": "Records to skip (pagination)"},
                "sort": {"type": "string", "description": "Sort: 'Column' or 'Column//DESC'"},
            },
            "required": ["table"],
        },
    ),
    Tool(
        name="get_record",
        description="Get a single record by ID",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "record_id": {"type": "integer", "description": "Record ID"},
                "columns": {"type": "array", "items": {"type": "string"}, "description": "Columns to return"},
            },
            "required": ["table", "record_id"],
        },
    ),
    Tool(
        name="create_record",
        description="Create a new record",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "data": {"type": "object", "description": "Record data (field: value)"},
                "suppress_triggers": {"type": "boolean", "description": "Suppress workflow triggers (default: false)"},
            },
            "required": ["table", "data"],
        },
    ),
    Tool(
        name="update_record",
        description="Update an existing record",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "record_id": {"type": "integer", "description": "Record ID"},
                "data": {"type": "object", "description": "Data to update (field: value)"},
                "suppress_triggers": {"type": "boolean", "description": "Suppress workflow triggers (default: false)"},
            },
            "required": ["table", "record_id", "data"],
        },
    ),
    Tool(
        name="delete_record",
        description="Delete a record",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "record_id": {"type": "integer", "description": "Record ID"},
            },
            "required": ["table", "record_id"],
        },
    ),
    Tool(
        name="upsert_records",
        description="Create or update records in batch (match by column)",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "match_column": {"type": "string", "description": "Column for match (must be Unique)"},
                "records": {"type": "array", "items": {"type": "object"}, "description": "Records to upsert"},
                "suppress_triggers": {"type": "boolean", "description": "Suppress workflow triggers (default: false)"},
            },
            "required": ["table", "match_column", "records"],
        },
    ),
    Tool(
        name="select_from_view",
        description="Query records from a specific view",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "view": {"type": "string", "description": "View name"},
                "top": {"type": "integer", "description": "Max records (default: 100)"},
            },
            "required": ["table", "view"],
        },
    ),
    Tool(
        name="search_records",
        description="Search records containing text. Auto-detects text columns if search_columns not provided.",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "search_text": {"type": "string", "description": "Text to search for"},
                "search_columns": {"type": "array", "items": {"type": "string"}, "description": "Columns to search IN (optional, auto-detects text columns if omitted)"},
                "columns": {"type": "array", "items": {"type": "string"}, "description": "Columns to return"},
                "top": {"type": "integer", "description": "Max results (default: 50)"},
            },
            "required": ["table", "search_text"],
        },
    ),
    Tool(
        name="get_attachment_url",
        description="Get download URL for a file attachment",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "column": {"type": "string", "description": "Attachment column name"},
                "record_id": {"type": "integer", "description": "Record ID"},
            },
            "required": ["table", "column", "record_id"],
        },
    ),
    Tool(
        name="smart_query",
        description="Query TeamDesk with automatic validation and correction of common mistakes. "
                    "Fixes accent errors, date formats, LIKE→Contains, AND→and. Use instead of get_records for safer queries.",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name (e.g. 'Usina Solar', 'Geracao Mensal', 'CUSD')"},
                "filter": {"type": "string", "description": "Filter expression (auto-corrected)"},
                "columns": {"type": "array", "items": {"type": "string"}, "description": "Columns to return (auto-corrected)"},
                "top": {"type": "integer", "description": "Max records (default: 100)"},
                "skip": {"type": "integer", "description": "Records to skip"},
                "sort": {"type": "string", "description": "Sort: 'Column' or 'Column//DESC'"},
            },
            "required": ["table"],
        },
    ),
    Tool(
        name="global_search",
        description="Search for text across ALL TeamDesk tables. Returns results grouped by table. "
                    "Use for finding records when you don't know which table contains the data.",
        inputSchema={
            "type": "object",
            "properties": {
                "search_text": {"type": "string", "description": "Text to search for (e.g. 'Paracatu', '3014576923')"},
                "tables": {"type": "array", "items": {"type": "string"}, "description": "Specific tables to search (optional, searches all if empty)"},
                "top_per_table": {"type": "integer", "description": "Max results per table (default: 5)"},
            },
            "required": ["search_text"],
        },
    ),
    Tool(
        name="aggregate_query",
        description="Run aggregation queries (SUM, AVG, COUNT, MIN, MAX) directly on TeamDesk. "
                    "Much more efficient than fetching all records. Supports grouping by date (MM, YY, DD, QQ) or value (EQ).",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "measure_column": {"type": "string", "description": "Column to aggregate (e.g. 'Geracao dia (kWh)')"},
                "measure_function": {"type": "string", "description": "SUM, COUNT, AVG, MIN, MAX, STDEV, VAR (default: SUM)"},
                "group_column": {"type": "string", "description": "Column to group by (optional)"},
                "group_function": {"type": "string", "description": "EQ (exact), MM (month), YY (year), DD (day), QQ (quarter), HH (hour)"},
                "filter": {"type": "string", "description": "Filter expression (optional)"},
                "top": {"type": "integer", "description": "Max groups (default: 500)"},
            },
            "required": ["table", "measure_column"],
        },
    ),
    Tool(
        name="count_records",
        description="Count records in a table without returning data. Much faster and lighter than fetching records.",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "filter": {"type": "string", "description": "Filter expression (optional)"},
            },
            "required": ["table"],
        },
    ),
    Tool(
        name="batch_delete",
        description="Delete multiple records at once (max 500).",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "record_ids": {"type": "array", "items": {"type": "integer"}, "description": "Record IDs to delete"},
                "purge": {"type": "boolean", "description": "Permanently delete without trash (default: false)"},
                "suppress_triggers": {"type": "boolean", "description": "Suppress workflow triggers (default: false)"},
            },
            "required": ["table", "record_ids"],
        },
    ),
    Tool(
        name="get_changes",
        description="Get records modified or deleted in a time range. Useful for incremental sync.",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "since": {"type": "string", "description": "Start datetime ISO 8601 (e.g. '2026-03-01T00:00:00')"},
                "until": {"type": "string", "description": "End datetime (optional, defaults to now)"},
                "change_type": {"type": "string", "description": "'updated' or 'deleted' (default: 'updated')"},
            },
            "required": ["table", "since"],
        },
    ),
    Tool(
        name="list_views",
        description="List all available views for a table",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
            },
            "required": ["table"],
        },
    ),
    Tool(
        name="relationship_map",
        description="Show relationships between tables (references, lookups, summaries). Returns Mermaid diagram.",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Specific table (optional, maps all if empty)"},
            },
            "required": [],
        },
    ),
    Tool(
        name="compare_records",
        description="Compare two records and show differences",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "record_id_1": {"type": "integer", "description": "First record ID"},
                "record_id_2": {"type": "integer", "description": "Second record ID"},
                "columns": {"type": "array", "items": {"type": "string"}, "description": "Columns to compare (optional)"},
            },
            "required": ["table", "record_id_1", "record_id_2"],
        },
    ),
    Tool(
        name="data_quality_report",
        description="Generate a data quality report: empty fields, duplicates, value distributions",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "sample_size": {"type": "integer", "description": "Records to analyze (default: 100)"},
            },
            "required": ["table"],
        },
    ),
]

# Schema cache for smart_query (avoids repeated describe_table calls)
_schema_cache: dict[str, dict] = {}
_table_list_cache: Optional[list[str]] = None

CACHEABLE_OPERATIONS = {"list_tables", "describe_table"}

# Module-level SSE transport for original /sse endpoint (Claude Code / mcp-remote clients)
_sse_transport = SseServerTransport("/messages")



# ============================================================================
# TOOL EXECUTION
# ============================================================================

rate_limiter = RateLimiter(max_requests=MCP_RATE_LIMIT)
cache = TTLCache(default_ttl=MCP_CACHE_TTL)
http_client = TeamDeskClient()
api_key_validator = ApiKeyValidator(cache_ttl=MCP_API_KEY_CACHE_TTL)
mcp_server = Server(
    "teamdesk-mcp-server",
    instructions="""Você é um assistente da ForGreen Energia Solar. Responda SEMPRE em português brasileiro.

FORMATAÇÃO (o usuário pode estar no celular):
- NUNCA use tabelas markdown. Use listas compactas com bullet points.
- Máximo 3-5 campos por registro. Priorize os mais relevantes.
- Para múltiplos registros, mostre um resumo (ex: "12 usinas encontradas") e liste os principais.
- Números grandes: use formato brasileiro (1.234,56) e abrevie (1,2 MW ao invés de 1200 kW).
- Datas: formato DD/MM/YYYY.

CONTEXTO:
- Database TeamDesk da ForGreen (energia solar, usinas fotovoltaicas, inversores, faturamento).
- Tabelas principais: Usina Solar, Inversor, Geração Mensal, Geracao_Dia, Cliente, Faturamento.
- Coluna de filtro por usina: [Instalação] (código numérico) ou [Nome da Usina].
""",
)



# ============================================================================
# RESOURCES — semi-static data the LLM can read without calling tools
# ============================================================================

GOTCHAS_DATA = {
    "filter_syntax": {
        "LIKE_not_supported": "Use Contains([Campo], 'valor') instead of LIKE '%valor%'",
        "operators_lowercase": "Use 'and', 'or', 'not' (lowercase). 'AND'/'OR' cause errors.",
        "dates_format": "Use #YYYY-MM-DD# (with hashes). Not 'YYYY-MM-DD' or DD/MM/YYYY.",
        "Contains_wildcard_broken": "Contains([*], 'text') does NOT work in REST API (400 error). Use schema-based search.",
    },
    "write_operations": {
        "body_must_be_array": "POST body must be [{...}], not {...}. Single object causes 405.",
        "update_requires_row_id": "Use '@row.id' (internal), NOT user-defined 'Id' column.",
        "scientific_notation": "Small floats (< 0.0001) serialize as '2e-05'. TeamDesk rejects. Use string format.",
        "suppress_triggers": "Add ?workflow=0 to suppress triggers (requires ManageData).",
        "delete_uses_GET": "DELETE endpoint uses GET method: GET /table/delete.json?id=123",
    },
    "column_names": {
        "accents_required": "Column names must use exact accents: Geração, Instalação, Irradiação, Potência, Mês.",
        "Sum_vs_plus": "Sum([A],[B],[C]) ignores nulls. [A]+[B]+[C] propagates null.",
    },
    "endpoints": {
        "select_endpoint": "Use /table/select.json (NOT /table.json — 405 error)",
        "document_no_json": "Document endpoint: /table/doc/document (NO .json suffix)",
        "sort_syntax": "Sort: 'Column//DESC' (double slash, not dash)",
    },
}

PROMPTS = [
    Prompt(
        name="consulta-geracao",
        description="Consultar geração de energia de uma usina",
        arguments=[
            PromptArgument(name="usina", description="Nome da usina (ex: Paracatu, Iturama)", required=True),
            PromptArgument(name="periodo", description="Período (ex: 'janeiro 2026', 'último mês')", required=False),
        ],
    ),
    Prompt(
        name="auditoria-tabela",
        description="Auditar qualidade dos dados de uma tabela",
        arguments=[
            PromptArgument(name="tabela", description="Nome da tabela", required=True),
        ],
    ),
    Prompt(
        name="debug-filter",
        description="Depurar um filtro que não retorna resultados",
        arguments=[
            PromptArgument(name="tabela", description="Nome da tabela", required=True),
            PromptArgument(name="filtro", description="Filtro que está falhando", required=True),
        ],
    ),
]


@mcp_server.list_resources()
async def handle_list_resources() -> list[Resource]:
    return [
        Resource(uri="teamdesk://gotchas", name="TeamDesk API Gotchas", description="Critical API gotchas that prevent common errors", mimeType="application/json"),
    ]


@mcp_server.read_resource()
async def handle_read_resource(uri) -> str:
    uri_str = str(uri)
    if uri_str == "teamdesk://gotchas":
        return json.dumps(GOTCHAS_DATA, indent=2, ensure_ascii=False)
    return json.dumps({"error": f"Unknown resource: {uri_str}"})


@mcp_server.list_prompts()
async def handle_list_prompts() -> list[Prompt]:
    return PROMPTS


@mcp_server.get_prompt()
async def handle_get_prompt(name: str, arguments: dict | None = None) -> GetPromptResult:
    args = arguments or {}

    if name == "consulta-geracao":
        usina = args.get("usina", "")
        periodo = args.get("periodo", "último mês")
        return GetPromptResult(
            description=f"Consultar geração de {usina}",
            messages=[PromptMessage(role="user", content=TextContent(
                type="text",
                text=f"""Consulte a geração de energia da usina "{usina}" no período "{periodo}".

Passos recomendados:
1. Use aggregate_query na tabela "Geracao_Dia" com measure_column="Geracao dia (kWh)", measure_function="SUM", group_column="Data", group_function="MM"
2. Filtre por Contains([Unidade Geradora], '{usina}') e o período
3. Compare com o P90 na tabela "Geração Mensal" (coluna "Geracao P90 (kWh)")
4. Calcule Performance Ratio: (Geração Real / P90) × 100

Formato brasileiro (1.234,56 kWh), lista compacta."""
            ))],
        )

    elif name == "auditoria-tabela":
        tabela = args.get("tabela", "")
        return GetPromptResult(
            description=f"Auditoria de {tabela}",
            messages=[PromptMessage(role="user", content=TextContent(
                type="text",
                text=f"""Audite a qualidade dos dados na tabela "{tabela}".

Passos:
1. describe_table para ver a estrutura
2. count_records para o total
3. aggregate_query com COUNT para verificar preenchimento por coluna
4. Detectar registros sem campos obrigatórios, valores fora do esperado (MIN/MAX), duplicatas

Reporte: total, % campos vazios, anomalias."""
            ))],
        )

    elif name == "debug-filter":
        tabela = args.get("tabela", "")
        filtro = args.get("filtro", "")
        return GetPromptResult(
            description=f"Debug filtro em {tabela}",
            messages=[PromptMessage(role="user", content=TextContent(
                type="text",
                text=f"""O filtro abaixo não retorna resultados na tabela "{tabela}":
```
{filtro}
```

Diagnóstico:
1. smart_query (auto-corrige acentos, datas, LIKE→Contains, AND→and)
2. count_records sem filtro (tabela tem dados?)
3. describe_table (nomes exatos das colunas)
4. Testar cada condição separadamente

Gotchas: Geracao→Geração, '2026-01-01'→#2026-01-01#, LIKE→Contains(), AND→and"""
            ))],
        )

    return GetPromptResult(description="Unknown prompt", messages=[])


@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return TOOLS


@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    token = current_user_token.get(None)
    if not token:
        return [TextContent(type="text", text=json.dumps({"error": "Authentication required"}))]

    user_key = current_user_key.get("unknown")
    allowed, remaining = await rate_limiter.is_allowed(user_key)
    if not allowed:
        return [TextContent(type="text", text=json.dumps({"error": "Rate limit exceeded"}))]

    result = await execute_tool(token, name, arguments)
    asyncio.create_task(api_key_validator.update_last_use(user_key, http_client))

    return [TextContent(
        type="text",
        text=json.dumps(result.get("result", result), indent=2, ensure_ascii=False),
    )]


async def execute_tool(token: str, name: str, args: dict) -> dict:
    if name in CACHEABLE_OPERATIONS:
        cached, hit = await cache.get(token, name, args)
        if hit:
            return {"result": cached, "cache": "HIT"}

    result = await _run_tool(token, name, args)

    if name in CACHEABLE_OPERATIONS and "error" not in result:
        await cache.set(token, name, args, result)

    return {"result": result, "cache": "MISS" if name in CACHEABLE_OPERATIONS else "SKIP"}


async def _run_tool(token: str, name: str, args: dict) -> dict:
    """Execute tool with corrected TeamDesk API endpoints."""
    logger.info(f"Tool: {name} | Args: {json.dumps(args, ensure_ascii=False)}")
    if args.get("table"):
        raw = args["table"]
        logger.info(f"Raw table name: {repr(raw)} | bytes: {raw.encode('utf-8').hex()}")

    if name == "list_tables":
        # CORRECT: describe.json (NOT tables.json)
        return await http_client.request("GET", token, "describe.json")

    elif name == "describe_table":
        err = validate_required(args, ["table"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        # CORRECT: {table}/describe.json (NOT {table}/columns.json)
        return await http_client.request("GET", token, f"{table}/describe.json")

    elif name == "get_records":
        err = validate_required(args, ["table"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        params = {}
        if args.get("filter"):
            params["filter"] = args["filter"]
        if args.get("columns"):
            params["column"] = args["columns"]
        if args.get("top"):
            params["top"] = min(args["top"], 1000)
        if args.get("skip"):
            params["skip"] = args["skip"]
        if args.get("sort"):
            # CORRECT: sort=Column//DESC (NOT separate desc param)
            params["sort"] = args["sort"]
        return await http_client.request("GET", token, f"{table}/select.json", params=params)

    elif name == "get_record":
        err = validate_required(args, ["table", "record_id"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        record_id = int(args["record_id"])
        params = {"id": record_id}
        if args.get("columns"):
            params["column"] = args["columns"]
        # CORRECT: {table}/retrieve.json?id=N (NOT {table}/{id}.json)
        return await http_client.request("GET", token, f"{table}/retrieve.json", params=params)

    elif name == "create_record":
        err = validate_required(args, ["table", "data"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        endpoint = f"{table}/create.json"
        params = {}
        if args.get("suppress_triggers"):
            params["workflow"] = 0
        return await http_client.request("POST", token, endpoint, params=params if params else None, json_data=[args["data"]])

    elif name == "update_record":
        err = validate_required(args, ["table", "record_id", "data"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        record_id = int(args["record_id"])
        update_data = {**args["data"], "@row.id": record_id}
        params = {}
        if args.get("suppress_triggers"):
            params["workflow"] = 0
        return await http_client.request("POST", token, f"{table}/update.json", params=params if params else None, json_data=[update_data])

    elif name == "delete_record":
        err = validate_required(args, ["table", "record_id"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        record_id = int(args["record_id"])
        # CORRECT: GET {table}/delete.json?id=N (NOT DELETE {table}/{id}.json)
        return await http_client.request("GET", token, f"{table}/delete.json", params={"id": record_id})

    elif name == "upsert_records":
        err = validate_required(args, ["table", "match_column", "records"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        params = {"match": args["match_column"]}
        if args.get("suppress_triggers"):
            params["workflow"] = 0
        return await http_client.request("POST", token, f"{table}/upsert.json", params=params, json_data=args["records"])

    elif name == "select_from_view":
        err = validate_required(args, ["table", "view"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        view = sanitize_table_name(args["view"])
        params = {"top": min(args.get("top", 100), 1000)}
        # CORRECT: {table}/{view}/select.json (NOT {view}/{table}/select.json)
        return await http_client.request("GET", token, f"{table}/{view}/select.json", params=params)

    elif name == "search_records":
        err = validate_required(args, ["table", "search_text"])
        if err:
            return {"error": err}
        raw_table = args["table"]
        table_enc = sanitize_table_name(raw_table)
        safe_text = sanitize_search_text(args["search_text"])
        _SEARCHABLE_TYPES = {"Text", "Multiline", "Link", "Email", "Phone", "URL"}
        _MAX_SEARCH_COLS = 10

        # Get schema to find searchable text columns (NOT broken [*] wildcard)
        if raw_table not in _schema_cache:
            schema_res = await http_client.request("GET", token, f"{table_enc}/describe.json")
            if "error" not in schema_res:
                _schema_cache[raw_table] = schema_res
        schema = _schema_cache.get(raw_table)
        if not schema:
            return {"error": f"Could not get schema for table '{raw_table}'"}
        text_cols = [
            c["name"] for c in schema.get("columns", [])
            if c.get("type") in _SEARCHABLE_TYPES
        ][:_MAX_SEARCH_COLS]
        if not text_cols:
            return {"error": f"No searchable text columns in table '{raw_table}'"}
        parts = [f"Contains([{col}], '{safe_text}')" for col in text_cols]
        search_filter = " or ".join(parts)

        params = {
            "filter": search_filter,
            "top": min(args.get("top", 50), 500),
        }
        if args.get("columns"):
            params["column"] = args["columns"]
        return await http_client.request("GET", token, f"{table_enc}/select.json", params=params)

    elif name == "get_attachment_url":
        err = validate_required(args, ["table", "column", "record_id"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        column = urllib.parse.quote(args["column"], safe="")
        record_id = int(args["record_id"])
        # CORRECT: {table}/{column}/attachment?id={row_id}
        # (NOT attachment.aspx?fid=...&guid=...)
        url = (
            f"{TEAMDESK_API_BASE}/{TEAMDESK_DATABASE_ID}"
            f"/{table}/{column}/attachment?id={record_id}"
        )
        return {"url": url}

    elif name == "smart_query":
        err = validate_required(args, ["table"])
        if err:
            return {"error": err}

        corrections_log = []

        # 1. Check and fix table name
        table_check = check_table_name(args["table"])
        if table_check["issues"]:
            corrections_log.extend(f"Tabela: {i['message']}" for i in table_check["issues"])
        resolved_table = table_check["corrected"]

        # 2. Get schema for column validation (with cache)
        schema = None
        if resolved_table in _schema_cache:
            schema = _schema_cache[resolved_table]
        else:
            table_enc = sanitize_table_name(resolved_table)
            schema_result = await http_client.request("GET", token, f"{table_enc}/describe.json")
            if "error" not in schema_result:
                _schema_cache[resolved_table] = schema_result
                schema = schema_result

        # 3. Check and fix filter
        resolved_filter = args.get("filter")
        if resolved_filter:
            filter_check = check_filter(resolved_filter, schema)
            if filter_check["issues"]:
                corrections_log.extend(f"Filtro: {i['message']}" for i in filter_check["issues"])
            resolved_filter = filter_check["corrected"]

        # 4. Check and fix columns
        resolved_columns = args.get("columns")
        if resolved_columns:
            col_check = check_columns(resolved_columns, schema)
            if col_check["issues"]:
                corrections_log.extend(f"Coluna: {i['message']}" for i in col_check["issues"])
            resolved_columns = col_check["corrected"]

        # 5. Execute the corrected query
        table_enc = sanitize_table_name(resolved_table)
        params = {}
        if resolved_filter:
            params["filter"] = resolved_filter
        if resolved_columns:
            params["column"] = resolved_columns
        if args.get("top"):
            params["top"] = min(args["top"], 1000)
        if args.get("skip"):
            params["skip"] = args["skip"]
        if args.get("sort"):
            params["sort"] = args["sort"]

        result = await http_client.request("GET", token, f"{table_enc}/select.json", params=params)

        if "error" in result:
            output = {
                "error": result["error"],
                "query_used": {"table": resolved_table, "filter": resolved_filter, "columns": resolved_columns},
            }
            if corrections_log:
                output["corrections_applied"] = corrections_log
            return output

        records = result if isinstance(result, list) else result.get("records", result)
        record_count = len(records) if isinstance(records, list) else 0

        # 6. Self-correction loop: if 0 results and filter exists, try broadening
        if record_count == 0 and resolved_filter:
            suggestions = broaden_filter(resolved_filter)
            for suggestion in suggestions:
                retry_params = {"top": 5 if suggestion["is_diagnostic"] else min(args.get("top", 100), 1000)}
                if suggestion["filter"]:
                    retry_params["filter"] = suggestion["filter"]
                if resolved_columns:
                    retry_params["column"] = resolved_columns
                if args.get("sort"):
                    retry_params["sort"] = args["sort"]

                retry_result = await http_client.request("GET", token, f"{table_enc}/select.json", params=retry_params)

                if "error" in retry_result:
                    continue

                retry_records = retry_result if isinstance(retry_result, list) else retry_result.get("records", retry_result)
                retry_count = len(retry_records) if isinstance(retry_records, list) else 0

                if retry_count > 0:
                    corrections_log.append(f"Self-correction: {suggestion['description']}")
                    if suggestion["is_diagnostic"]:
                        output = {
                            "records": [],
                            "count": 0,
                            "_self_correction": {
                                "status": "original_filter_too_narrow",
                                "message": f"Filtro original retornou 0 resultados, mas tabela tem dados ({retry_count}+ registros). Revise o filtro.",
                                "original_filter": resolved_filter,
                                "sample_record": retry_records[0] if retry_records else None,
                            },
                        }
                    else:
                        output = {
                            "records": retry_records,
                            "count": retry_count,
                            "_self_correction": {
                                "status": "broadened",
                                "strategy": suggestion["strategy"],
                                "message": suggestion["description"],
                                "original_filter": resolved_filter,
                                "broadened_filter": suggestion["filter"],
                            },
                        }
                    if corrections_log:
                        output["_corrections"] = corrections_log
                    return output

        # 7. Build response
        output = {"records": records, "count": record_count}
        if corrections_log:
            output["_corrections"] = corrections_log
            output["_note"] = "Query foi corrigida automaticamente antes da execução"
        return output

    elif name == "global_search":
        err = validate_required(args, ["search_text"])
        if err:
            return {"error": err}

        search_text = args["search_text"].strip()
        if not search_text:
            return {"error": "search_text cannot be empty"}

        safe_text = sanitize_search_text(search_text)
        top_per_table = min(args.get("top_per_table", 5), 50)
        _SEARCHABLE_TYPES = {"Text", "Multiline", "Link", "Email", "Phone", "URL"}
        _MAX_SEARCH_COLS = 10

        # Get table list
        table_names = args.get("tables")
        if not table_names:
            global _table_list_cache
            if _table_list_cache is None:
                desc = await http_client.request("GET", token, "describe.json")
                if "error" not in desc:
                    _table_list_cache = [t["recordName"] for t in desc.get("tables", [])]
            table_names = _table_list_cache or []
            if not table_names:
                return {"error": "Could not retrieve table list"}

        # Phase 1: Fetch schemas in parallel (for text column discovery)
        sem = asyncio.Semaphore(8)

        async def get_schema_cached(tbl: str) -> tuple[str, Optional[dict]]:
            if tbl in _schema_cache:
                return tbl, _schema_cache[tbl]
            async with sem:
                tbl_enc = sanitize_table_name(tbl)
                res = await http_client.request("GET", token, f"{tbl_enc}/describe.json")
                if "error" not in res:
                    _schema_cache[tbl] = res
                    return tbl, res
                return tbl, None

        schema_tasks = [get_schema_cached(t) for t in table_names]
        schema_results = await asyncio.gather(*schema_tasks)

        # Build filters per table using real text columns
        table_filters = {}
        skipped = []
        for tbl, schema in schema_results:
            if not schema:
                skipped.append(tbl)
                continue
            text_cols = [
                c["name"] for c in schema.get("columns", [])
                if c.get("type") in _SEARCHABLE_TYPES
            ][:_MAX_SEARCH_COLS]
            if not text_cols:
                skipped.append(tbl)
                continue
            parts = [f"Contains([{col}], '{safe_text}')" for col in text_cols]
            table_filters[tbl] = " or ".join(parts)

        # Phase 2: Search in parallel
        async def search_one(tbl: str, filt: str) -> tuple[str, dict]:
            async with sem:
                tbl_enc = sanitize_table_name(tbl)
                params = {"filter": filt, "top": top_per_table}
                try:
                    res = await http_client.request("GET", token, f"{tbl_enc}/select.json", params=params)
                    return tbl, res
                except Exception as e:
                    return tbl, {"error": str(e)}

        search_tasks = [search_one(t, f) for t, f in table_filters.items()]
        raw_results = await asyncio.gather(*search_tasks)

        results = {}
        errors = {}
        for tbl, res in raw_results:
            if "error" in res:
                errors[tbl] = res["error"]
                continue
            records = res if isinstance(res, list) else res.get("records", res)
            count = len(records) if isinstance(records, list) else 0
            if count > 0:
                results[tbl] = {"count": count, "records": records}

        output = {
            "search_text": search_text,
            "tables_searched": len(table_filters),
            "tables_with_results": len(results),
            "results": results,
        }
        if errors:
            output["errors"] = errors
        return output

    elif name == "aggregate_query":
        err = validate_required(args, ["table", "measure_column"])
        if err:
            return {"error": err}
        table_check = check_table_name(args["table"])
        resolved_table = table_check["corrected"]
        table_enc = sanitize_table_name(resolved_table)

        # Build column params with aggregation suffixes
        columns = []
        if args.get("group_column"):
            gf = args.get("group_function", "EQ")
            columns.append(f"{args['group_column']}//{gf}")
        mf = (args.get("measure_function") or "SUM").upper()
        valid_funcs = ("SUM", "COUNT", "AVG", "MIN", "MAX", "STDEV", "STDEVP", "VAR", "VARP")
        if mf not in valid_funcs:
            return {"error": f"Invalid measure_function: {mf}. Use {', '.join(valid_funcs)}."}
        columns.append(f"{args['measure_column']}//{mf}")

        params = {"column": columns, "top": min(args.get("top", 500), 500)}
        if args.get("filter"):
            # Get schema for filter validation
            if resolved_table not in _schema_cache:
                schema_res = await http_client.request("GET", token, f"{table_enc}/describe.json")
                if "error" not in schema_res:
                    _schema_cache[resolved_table] = schema_res
            schema = _schema_cache.get(resolved_table)
            filter_check = check_filter(args["filter"], schema)
            params["filter"] = filter_check["corrected"]

        return await http_client.request("GET", token, f"{table_enc}/select.json", params=params)

    elif name == "count_records":
        err = validate_required(args, ["table"])
        if err:
            return {"error": err}
        table_check = check_table_name(args["table"])
        resolved_table = table_check["corrected"]
        table_enc = sanitize_table_name(resolved_table)

        # Get key column for COUNT aggregation
        if resolved_table not in _schema_cache:
            schema_res = await http_client.request("GET", token, f"{table_enc}/describe.json")
            if "error" not in schema_res:
                _schema_cache[resolved_table] = schema_res
        schema = _schema_cache.get(resolved_table)
        key_col = None
        if schema:
            for col in schema.get("columns", []):
                if col.get("isKey"):
                    key_col = col["name"]
                    break
            if not key_col and schema.get("columns"):
                key_col = schema["columns"][0]["name"]
        if not key_col:
            return {"error": "Could not determine a column for COUNT"}

        params = {"column": [f"{key_col}//COUNT"], "top": 1}
        if args.get("filter"):
            filter_check = check_filter(args["filter"], schema)
            params["filter"] = filter_check["corrected"]

        result = await http_client.request("GET", token, f"{table_enc}/select.json", params=params)
        if "error" in result:
            return result

        # Extract count from aggregation
        records = result if isinstance(result, list) else result.get("records", result)
        count = 0
        if isinstance(records, list) and records:
            for v in records[0].values():
                if isinstance(v, (int, float)):
                    count = int(v)
                    break
        return {"table": resolved_table, "count": count, "filter": args.get("filter")}

    elif name == "batch_delete":
        err = validate_required(args, ["table", "record_ids"])
        if err:
            return {"error": err}
        table_enc = sanitize_table_name(args["table"])
        ids = args["record_ids"]
        if not ids:
            return {"error": "No record IDs provided"}
        if len(ids) > 500:
            return {"error": "Maximum 500 records per batch delete"}

        params = [("id", rid) for rid in ids]
        if args.get("purge"):
            params.append(("purge", 1))
        if args.get("suppress_triggers"):
            params.append(("workflow", 0))

        qs = urllib.parse.urlencode(params, doseq=True)
        result = await http_client.request("GET", token, f"{table_enc}/delete.json?{qs}")
        if "error" in result:
            return result
        return {"success": True, "deleted_ids": ids, "count": len(ids)}

    elif name == "get_changes":
        err = validate_required(args, ["table", "since"])
        if err:
            return {"error": err}
        table_check = check_table_name(args["table"])
        resolved_table = table_check["corrected"]
        table_enc = sanitize_table_name(resolved_table)

        change_type = args.get("change_type", "updated")
        if change_type not in ("updated", "deleted"):
            return {"error": "change_type must be 'updated' or 'deleted'"}

        params = {"from": args["since"]}
        if args.get("until"):
            params["to"] = args["until"]

        result = await http_client.request("GET", token, f"{table_enc}/{change_type}.json", params=params)
        if "error" in result:
            return result

        records = result if isinstance(result, list) else result.get("records", result)
        count = len(records) if isinstance(records, list) else 0
        return {
            "table": resolved_table,
            "change_type": change_type,
            "since": args["since"],
            "until": args.get("until"),
            "count": count,
            "records": records,
        }

    elif name == "list_views":
        err = validate_required(args, ["table"])
        if err:
            return {"error": err}
        table_check = check_table_name(args["table"])
        resolved_table = table_check["corrected"]
        table_enc = sanitize_table_name(resolved_table)

        if resolved_table not in _schema_cache:
            schema_res = await http_client.request("GET", token, f"{table_enc}/describe.json")
            if "error" not in schema_res:
                _schema_cache[resolved_table] = schema_res
        schema = _schema_cache.get(resolved_table)
        if not schema:
            return {"error": f"Could not get schema for '{resolved_table}'"}

        views = schema.get("views", [])
        return {
            "table": resolved_table,
            "views": [{"name": v.get("name"), "type": v.get("type", "?"), "id": v.get("id")} for v in views],
            "count": len(views),
        }

    elif name == "relationship_map":
        raw_table = args.get("table")
        if raw_table:
            tables_to_scan = [check_table_name(raw_table)["corrected"]]
        else:
            if _table_list_cache is None:
                desc = await http_client.request("GET", token, "describe.json")
                if "error" not in desc:
                    _table_list_cache = [t["recordName"] for t in desc.get("tables", [])]
            tables_to_scan = _table_list_cache or []
            if not tables_to_scan:
                return {"error": "Could not get table list"}

        # Fetch schemas in parallel
        sem = asyncio.Semaphore(8)

        async def get_schema_for_rel(tbl):
            if tbl in _schema_cache:
                return tbl, _schema_cache[tbl]
            async with sem:
                tbl_enc = sanitize_table_name(tbl)
                res = await http_client.request("GET", token, f"{tbl_enc}/describe.json")
                if "error" not in res:
                    _schema_cache[tbl] = res
                    return tbl, res
                return tbl, None

        schema_results = await asyncio.gather(*[get_schema_for_rel(t) for t in tables_to_scan])

        relationships = []
        for tbl, schema in schema_results:
            if not schema:
                continue
            for col in schema.get("columns", []):
                col_type = col.get("type", "")
                if col_type in ("Link", "Reference", "Lookup", "Summary"):
                    rel = {"from_table": tbl, "column": col["name"], "type": col_type}
                    if col.get("relatedTable"):
                        rel["to_table"] = col["relatedTable"]
                    elif col.get("options", {}).get("table"):
                        rel["to_table"] = col["options"]["table"]
                    relationships.append(rel)

        mermaid_lines = ["graph LR"]
        seen = set()
        for r in relationships:
            if r.get("to_table") and r["type"] in ("Link", "Reference"):
                key = f"{r['from_table']}-->{r['to_table']}"
                if key not in seen:
                    sf = r["from_table"].replace(" ", "_")
                    st = r["to_table"].replace(" ", "_")
                    mermaid_lines.append(f"    {sf} -->|{r['column']}| {st}")
                    seen.add(key)

        return {
            "relationships": relationships,
            "count": len(relationships),
            "mermaid": "\n".join(mermaid_lines) if len(mermaid_lines) > 1 else None,
        }

    elif name == "compare_records":
        err = validate_required(args, ["table", "record_id_1", "record_id_2"])
        if err:
            return {"error": err}
        table_check = check_table_name(args["table"])
        resolved_table = table_check["corrected"]
        table_enc = sanitize_table_name(resolved_table)

        params1 = {"id": int(args["record_id_1"])}
        params2 = {"id": int(args["record_id_2"])}
        if args.get("columns"):
            params1["column"] = args["columns"]
            params2["column"] = args["columns"]

        r1, r2 = await asyncio.gather(
            http_client.request("GET", token, f"{table_enc}/retrieve.json", params=params1),
            http_client.request("GET", token, f"{table_enc}/retrieve.json", params=params2),
        )

        if "error" in r1:
            return {"error": f"Record {args['record_id_1']}: {r1['error']}"}
        if "error" in r2:
            return {"error": f"Record {args['record_id_2']}: {r2['error']}"}

        rec1 = r1[0] if isinstance(r1, list) and r1 else r1
        rec2 = r2[0] if isinstance(r2, list) and r2 else r2

        all_keys = set(list(rec1.keys()) + list(rec2.keys()))
        differences = {}
        same_count = 0
        for key in sorted(all_keys):
            v1 = rec1.get(key)
            v2 = rec2.get(key)
            if v1 != v2:
                differences[key] = {"record_1": v1, "record_2": v2}
            else:
                same_count += 1

        return {
            "table": resolved_table,
            "record_1_id": args["record_id_1"],
            "record_2_id": args["record_id_2"],
            "differences": differences,
            "diff_count": len(differences),
            "same_count": same_count,
        }

    elif name == "data_quality_report":
        err = validate_required(args, ["table"])
        if err:
            return {"error": err}
        table_check = check_table_name(args["table"])
        resolved_table = table_check["corrected"]
        table_enc = sanitize_table_name(resolved_table)

        if resolved_table not in _schema_cache:
            schema_res = await http_client.request("GET", token, f"{table_enc}/describe.json")
            if "error" not in schema_res:
                _schema_cache[resolved_table] = schema_res
        schema = _schema_cache.get(resolved_table)
        if not schema:
            return {"error": f"Could not get schema for '{resolved_table}'"}

        columns = schema.get("columns", [])
        col_names = [c["name"] for c in columns if not c.get("isSystem")]

        sample_size = min(args.get("sample_size", 100), 500)
        result = await http_client.request("GET", token, f"{table_enc}/select.json", params={"top": sample_size})

        if "error" in result:
            return result

        records = result if isinstance(result, list) else result.get("records", result)
        total = len(records) if isinstance(records, list) else 0
        if total == 0:
            return {"table": resolved_table, "total_records": 0, "message": "Table is empty"}

        col_stats = {}
        for col in col_names:
            values = [r.get(col) for r in records if col in r]
            non_null = [v for v in values if v is not None and v != "" and v != 0]
            null_count = total - len(non_null)
            stat = {
                "empty_count": null_count,
                "empty_pct": round(null_count / total * 100, 1),
                "filled_count": len(non_null),
            }
            if non_null and isinstance(non_null[0], str):
                unique = len(set(non_null))
                if unique < len(non_null):
                    stat["duplicate_values"] = len(non_null) - unique
            col_stats[col] = stat

        empty_cols = sorted(
            [(k, v["empty_pct"]) for k, v in col_stats.items() if v["empty_pct"] > 0],
            key=lambda x: x[1], reverse=True,
        )

        return {
            "table": resolved_table,
            "records_analyzed": total,
            "total_columns": len(col_names),
            "columns_with_empties": len(empty_cols),
            "worst_empty_columns": empty_cols[:10],
            "column_details": col_stats,
        }

    return {"error": f"Unknown tool: {name}"}


# ============================================================================
# HTTP ENDPOINTS
# ============================================================================


async def setup_endpoint(request: Request) -> JSONResponse:
    """Validates API key and returns token for local MCP configuration."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return JSONResponse({"error": "X-API-Key header required"}, status_code=401)

    validation = await api_key_validator.validate(api_key, http_client)
    if not validation.valid:
        return JSONResponse({"error": validation.error}, status_code=401)

    return JSONResponse({
        "valid": True,
        "name": validation.user_name,
        "token": validation.token,
        "database_id": TEAMDESK_DATABASE_ID,
    })


async def health_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "healthy",
        "service": "teamdesk-mcp-server",
        "version": "3.3.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


async def test_encoding_endpoint(request: Request) -> JSONResponse:
    """Diagnostic endpoint to verify UTF-8 encoding through the entire stack."""
    text = request.query_params.get("text", "Geração Irradiação Mês ºC")
    return JSONResponse({
        "received": text,
        "repr": repr(text),
        "bytes_hex": text.encode("utf-8").hex(),
        "url_encoded": urllib.parse.quote(text, safe=""),
        "round_trip": urllib.parse.unquote(urllib.parse.quote(text, safe="")),
        "match": text == urllib.parse.unquote(urllib.parse.quote(text, safe="")),
        "sys_encoding": sys.getdefaultencoding(),
        "stdout_encoding": sys.stdout.encoding,
        "lang": os.environ.get("LANG", "NOT SET"),
        "lc_all": os.environ.get("LC_ALL", "NOT SET"),
    })


async def tools_list_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({
        "tools": [
            {"name": t.name, "description": t.description, "inputSchema": t.inputSchema}
            for t in TOOLS
        ]
    })


async def tools_call_endpoint(request: Request) -> Response:
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    allowed, remaining = await rate_limiter.is_allowed(client_ip)
    headers = {
        "X-RateLimit-Limit": str(MCP_RATE_LIMIT),
        "X-RateLimit-Remaining": str(remaining),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    if not allowed:
        return JSONResponse(
            {"error": "Rate limit exceeded"}, status_code=429, headers=headers,
        )

    # API key from header ONLY (no query param)
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return JSONResponse(
            {"error": "API key required (header X-API-Key)"}, status_code=401, headers=headers,
        )

    validation = await api_key_validator.validate(api_key, http_client)
    if not validation.valid:
        return JSONResponse(
            {"error": validation.error}, status_code=401, headers=headers,
        )

    token = validation.token
    headers["X-User"] = validation.user_name or "unknown"

    content_length = request.headers.get("Content-Length")
    if content_length and int(content_length) > MCP_MAX_PAYLOAD_SIZE:
        return JSONResponse(
            {"error": f"Payload exceeds {MCP_MAX_PAYLOAD_SIZE} bytes"},
            status_code=413, headers=headers,
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON body"}, status_code=400, headers=headers,
        )

    tool_name = body.get("name")
    arguments = body.get("arguments", {})

    if not tool_name:
        return JSONResponse(
            {"error": "Field 'name' is required"}, status_code=400, headers=headers,
        )

    valid_tools = {t.name for t in TOOLS}
    if tool_name not in valid_tools:
        return JSONResponse(
            {"error": f"Tool '{tool_name}' not found. Available: {', '.join(sorted(valid_tools))}"},
            status_code=404, headers=headers,
        )

    result = await execute_tool(token, tool_name, arguments)
    headers["X-Cache"] = result.get("cache", "SKIP")

    if isinstance(result.get("result"), dict) and "error" in result["result"]:
        sc = result["result"].get("status", 400)
        return JSONResponse({"error": result["result"]["error"]}, status_code=sc, headers=headers)

    # Update last use in background
    if validation.api_key:
        asyncio.create_task(api_key_validator.update_last_use(validation.api_key, http_client))

    return JSONResponse({"result": result["result"]}, status_code=200, headers=headers)


class _SseHandler:
    """ASGI handler for /sse - original SSE endpoint for Claude Code / mcp-remote."""

    async def __call__(self, scope, receive, send):
        request = Request(scope, receive, send)
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            response = JSONResponse({"error": "API key required (header X-API-Key)"}, status_code=401)
            await response(scope, receive, send)
            return

        validation = await api_key_validator.validate(api_key, http_client)
        if not validation.valid:
            response = JSONResponse({"error": validation.error}, status_code=401)
            await response(scope, receive, send)
            return

        logger.info(f"SSE connect: {validation.user_name} ({api_key[:12]}...)")
        current_user_token.set(validation.token)
        current_user_key.set(api_key)
        asyncio.create_task(api_key_validator.update_last_use(api_key, http_client))

        async with _sse_transport.connect_sse(scope, receive, send) as streams:
            await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())


# ============================================================================
# MOBILE STREAMABLE HTTP ENDPOINTS (Claude.ai / Claude mobile app)
# Uses the newer Streamable HTTP protocol instead of SSE.
# ============================================================================

# Session manager for mobile endpoints (stateful - maintains session across requests)
mobile_session_manager = StreamableHTTPSessionManager(
    app=mcp_server,
    json_response=False,
    stateless=False,
)


class _MobileStreamableHandler:
    """ASGI handler for /m/{chave}/sse - Streamable HTTP protocol for claude.ai."""

    async def __call__(self, scope, receive, send):
        chave = scope.get("path_params", {}).get("chave", "")
        if not chave or not validate_api_key_format(chave):
            response = Response(status_code=404)
            await response(scope, receive, send)
            return

        validation = await api_key_validator.validate(chave, http_client)
        if not validation.valid:
            response = Response(status_code=404)
            await response(scope, receive, send)
            return

        logger.info(f"Mobile connect: {validation.user_name} ({chave[:12]}...)")
        current_user_token.set(validation.token)
        current_user_key.set(chave)
        asyncio.create_task(api_key_validator.update_last_use(chave, http_client))

        # Ensure Accept header includes required values for Streamable HTTP
        # (claude.ai may not send them on initial request, causing 406)
        headers = list(scope.get("headers", []))
        has_accept = False
        for i, (name, value) in enumerate(headers):
            if name == b"accept":
                has_accept = True
                val = value.decode("latin-1")
                if "text/event-stream" not in val or "application/json" not in val:
                    headers[i] = (b"accept", b"application/json, text/event-stream")
                break
        if not has_accept:
            headers.append((b"accept", b"application/json, text/event-stream"))
        scope["headers"] = headers

        await mobile_session_manager.handle_request(scope, receive, send)


# ============================================================================
# ASGI HANDLERS for SSE message endpoints (Claude Code / mcp-remote)
# ============================================================================


class _MessagesHandler:
    """ASGI handler for /messages - routes POST to original SSE transport."""

    async def __call__(self, scope, receive, send):
        await _sse_transport.handle_post_message(scope, receive, send)


# ============================================================================
# OAUTH 2.0 ENDPOINTS (Required by claude.ai custom connectors)
# Implements RFC 9728, RFC 8414, RFC 7591, and PKCE (RFC 7636)
# ============================================================================

# In-memory stores (ephemeral - cleared on container restart)
_oauth_clients: dict[str, dict] = {}   # client_id -> registration data
_oauth_codes: dict[str, dict] = {}     # code -> {client_id, code_challenge, ...}
_oauth_tokens: dict[str, dict] = {}    # access_token -> {client_id, expires_at}


async def oauth_protected_resource(request: Request) -> JSONResponse:
    """RFC 9728 - OAuth Protected Resource Metadata."""
    return JSONResponse({
        "resource": MCP_PUBLIC_URL,
        "authorization_servers": [MCP_PUBLIC_URL],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    })


async def oauth_authorization_server(request: Request) -> JSONResponse:
    """RFC 8414 - OAuth Authorization Server Metadata."""
    return JSONResponse({
        "issuer": MCP_PUBLIC_URL,
        "authorization_endpoint": f"{MCP_PUBLIC_URL}/authorize",
        "token_endpoint": f"{MCP_PUBLIC_URL}/token",
        "registration_endpoint": f"{MCP_PUBLIC_URL}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [],
    })


async def oauth_register(request: Request) -> JSONResponse:
    """RFC 7591 - Dynamic Client Registration."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    client_id = str(uuid.uuid4())
    _oauth_clients[client_id] = {
        "client_id": client_id,
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", "unknown"),
        "created_at": time.time(),
    }

    # Cleanup old registrations (keep last 100)
    if len(_oauth_clients) > 100:
        oldest = sorted(_oauth_clients, key=lambda k: _oauth_clients[k]["created_at"])
        for k in oldest[:len(_oauth_clients) - 100]:
            del _oauth_clients[k]

    logger.info(f"OAuth register: {body.get('client_name', 'unknown')} -> {client_id[:8]}...")
    return JSONResponse({
        "client_id": client_id,
        "client_name": body.get("client_name", "unknown"),
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": "none",
    }, status_code=201)


async def oauth_authorize(request: Request) -> Response:
    """OAuth 2.0 Authorization Endpoint - auto-approves for MCP."""
    client_id = request.query_params.get("client_id", "")
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")

    if not client_id or not redirect_uri:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    # Generate authorization code
    code = secrets.token_urlsafe(32)
    _oauth_codes[code] = {
        "client_id": client_id,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "redirect_uri": redirect_uri,
        "expires_at": time.time() + 300,
    }

    # Cleanup expired codes
    now = time.time()
    expired = [k for k, v in _oauth_codes.items() if now > v["expires_at"]]
    for k in expired:
        del _oauth_codes[k]

    # Auto-redirect back with code (no user approval UI needed)
    params = {"code": code}
    if state:
        params["state"] = state

    sep = "&" if "?" in redirect_uri else "?"
    redirect_url = redirect_uri + sep + urllib.parse.urlencode(params)
    logger.info(f"OAuth authorize: client={client_id[:8]}... -> code issued")
    return Response(status_code=302, headers={"Location": redirect_url})


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 Token Endpoint with PKCE S256 verification."""
    try:
        body = await request.body()
        params = urllib.parse.parse_qs(body.decode("utf-8"))
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = params.get("grant_type", [""])[0]
    code = params.get("code", [""])[0]
    code_verifier = params.get("code_verifier", [""])[0]

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code_data = _oauth_codes.pop(code, None)
    if not code_data or time.time() > code_data["expires_at"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # Verify PKCE S256
    if code_data["code_challenge"] and code_verifier:
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if expected != code_data["code_challenge"]:
            logger.warning(f"OAuth token: PKCE verification failed")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # Issue access token
    access_token = secrets.token_urlsafe(48)
    _oauth_tokens[access_token] = {
        "client_id": code_data["client_id"],
        "expires_at": time.time() + 86400,
    }

    # Cleanup expired tokens
    now = time.time()
    expired = [k for k, v in _oauth_tokens.items() if now > v["expires_at"]]
    for k in expired:
        del _oauth_tokens[k]

    logger.info(f"OAuth token: issued for client={code_data['client_id'][:8]}...")
    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,
    })


# ============================================================================
# MOBILE SSE ENDPOINTS (Claude.ai / Claude mobile app)
# ============================================================================

# Registry of transports per user key (one per user, ~4 users)
_mobile_transports: dict[str, SseServerTransport] = {}


def _get_mobile_transport(chave: str) -> SseServerTransport:
    if chave not in _mobile_transports:
        _mobile_transports[chave] = SseServerTransport(f"/m/{chave}/messages")
    return _mobile_transports[chave]


async def mobile_sse_endpoint(request: Request):
    """SSE endpoint for Claude.ai/mobile - auth via URL path."""
    chave = request.path_params.get("chave", "")
    if not chave or not validate_api_key_format(chave):
        return Response(status_code=404)

    validation = await api_key_validator.validate(chave, http_client)
    if not validation.valid:
        return Response(status_code=404)

    logger.info(f"Mobile SSE connect: {validation.user_name} ({chave[:12]}...)")
    current_user_token.set(validation.token)
    current_user_key.set(chave)
    asyncio.create_task(api_key_validator.update_last_use(chave, http_client))

    transport = _get_mobile_transport(chave)
    async with transport.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())


async def mobile_messages_endpoint(request: Request):
    """JSON-RPC messages for Claude.ai/mobile - auth via URL path."""
    chave = request.path_params.get("chave", "")
    if not chave or not validate_api_key_format(chave):
        return Response(status_code=404)

    validation = await api_key_validator.validate(chave, http_client)
    if not validation.valid:
        return Response(status_code=404)

    current_user_token.set(validation.token)
    current_user_key.set(chave)

    transport = _get_mobile_transport(chave)
    await transport.handle_post_message(request.scope, request.receive, request._send)


# ============================================================================
# APP LIFECYCLE
# ============================================================================


async def cleanup_task():
    while True:
        await asyncio.sleep(60)
        await rate_limiter.cleanup()
        await cache.cleanup()
        await api_key_validator.cleanup()


@asynccontextmanager
async def lifespan(app):
    await http_client.start()
    async with mobile_session_manager.run():
        task = asyncio.create_task(cleanup_task())
        logger.info(f"TeamDesk MCP Server v3.3.0 (21 tools + resources + prompts, SSE + Streamable HTTP)")
        logger.info(f"Host: {MCP_HOST}:{MCP_PORT}")
        logger.info(f"Database: {'configured' if TEAMDESK_DATABASE_ID else 'NOT SET'}")
        logger.info(f"Master Token: {'configured' if TEAMDESK_MASTER_TOKEN else 'NOT SET'}")
        logger.info(f"Locale: LANG={os.environ.get('LANG', 'NOT SET')}, "
                    f"LC_ALL={os.environ.get('LC_ALL', 'NOT SET')}, "
                    f"stdout={sys.stdout.encoding}, default={sys.getdefaultencoding()}")
        logger.info(f"UTF-8 test: Geração Irradiação Mês ºC")
        yield
        task.cancel()
    await http_client.stop()


# Restrictive CORS: no wildcard by default
cors_origins = [o.strip() for o in MCP_CORS_ORIGINS if o.strip()]
# Always allow Claude.ai for mobile MCP connector
if "https://claude.ai" not in cors_origins:
    cors_origins.append("https://claude.ai")

routes = [
    # OAuth 2.0 endpoints (required by claude.ai custom connectors)
    Route("/.well-known/oauth-protected-resource/{path:path}", oauth_protected_resource, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
    Route("/register", oauth_register, methods=["POST"]),
    Route("/authorize", oauth_authorize, methods=["GET"]),
    Route("/token", oauth_token, methods=["POST"]),
    # Existing endpoints
    Route("/health", health_endpoint, methods=["GET"]),
    Route("/setup", setup_endpoint, methods=["GET"]),
    Route("/test-encoding", test_encoding_endpoint, methods=["GET"]),
    Route("/tools", tools_list_endpoint, methods=["GET"]),
    Route("/tools/call", tools_call_endpoint, methods=["POST"]),
    Route("/sse", _SseHandler()),
    Route("/messages", _MessagesHandler()),
    Route("/m/{chave}/sse", _MobileStreamableHandler()),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
        expose_headers=["X-Cache", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    ),
]

app = Starlette(debug=False, routes=routes, middleware=middleware, lifespan=lifespan)


def main():
    import uvicorn

    if not TEAMDESK_DATABASE_ID:
        print("ERROR: TEAMDESK_DATABASE_ID not set")
        return
    if not TEAMDESK_MASTER_TOKEN:
        print("ERROR: TEAMDESK_MASTER_TOKEN not set")
        return

    uvicorn.run(app, host=MCP_HOST, port=MCP_PORT, log_level="info")


if __name__ == "__main__":
    main()
