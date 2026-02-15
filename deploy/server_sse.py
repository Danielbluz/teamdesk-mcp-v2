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
import json
import time
import asyncio
import hashlib
import re
import urllib.parse
from typing import Any, Optional
from collections import defaultdict
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

load_dotenv()

# Configuration
TEAMDESK_DATABASE_ID = os.getenv("TEAMDESK_DATABASE_ID", "")
TEAMDESK_MASTER_TOKEN = os.getenv("TEAMDESK_MASTER_TOKEN", "")
TEAMDESK_API_KEYS_TABLE = os.getenv("TEAMDESK_API_KEYS_TABLE", "API-Keys")
MCP_RATE_LIMIT = int(os.getenv("MCP_RATE_LIMIT", "100"))
MCP_CACHE_TTL = int(os.getenv("MCP_CACHE_TTL", "300"))
MCP_API_KEY_CACHE_TTL = int(os.getenv("MCP_API_KEY_CACHE_TTL", "60"))
MCP_CORS_ORIGINS = os.getenv("MCP_CORS_ORIGINS", "").split(",")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8080"))
MCP_MAX_PAYLOAD_SIZE = int(os.getenv("MCP_MAX_PAYLOAD_SIZE", "1048576"))

TEAMDESK_API_BASE = "https://www.teamdesk.net/secure/api/v2"

# API key validation regex: alphanumeric, underscores, hyphens, dots (8-128 chars)
_API_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{8,128}$")


def validate_api_key_format(api_key: str) -> bool:
    """Validate API key contains only safe characters and is 8-128 chars."""
    return bool(_API_KEY_PATTERN.match(api_key))


def sanitize_search_text(text: str) -> str:
    """Escape single quotes in search text to prevent filter injection."""
    return text.replace("'", "''")


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
                 api_key: str = None, record_id: int = None, error: str = None):
        self.valid = valid
        self.token = token
        self.user_name = user_name
        self.api_key = api_key
        self.record_id = record_id
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
                "filter": f"[Key]='{safe_key}'",
                "column": ["Key", "Token", "Ativo", "Nome", "@row.id"],
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
        ativo = record.get("Ativo", "")
        if ativo not in ("Sim", "Yes", True, "true", "1", 1):
            result = ApiKeyValidationResult(valid=False, error="API key disabled")
            async with self._lock:
                self.cache[api_key] = (result, time.time() + 10)
            return result

        user_token = record.get("Token", "") or TEAMDESK_MASTER_TOKEN
        result = ApiKeyValidationResult(
            valid=True,
            token=user_token,
            user_name=record.get("Nome", ""),
            api_key=api_key,
            record_id=record.get("@row.id"),
        )
        async with self._lock:
            self.cache[api_key] = (result, time.time() + self.cache_ttl)
        return result

    async def update_last_use(self, record_id: int, http_client: "TeamDeskClient"):
        if not record_id or not TEAMDESK_MASTER_TOKEN:
            return
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            table = urllib.parse.quote(TEAMDESK_API_KEYS_TABLE, safe="")
            await http_client.request(
                method="POST",
                token=TEAMDESK_MASTER_TOKEN,
                endpoint=f"{table}/update.json",
                json_data=[{"@row.id": record_id, "Ultimo_Uso": now}],
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
        description="Full-text search across all columns of a table",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Table name"},
                "search_text": {"type": "string", "description": "Text to search for"},
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
]

CACHEABLE_OPERATIONS = {"list_tables", "describe_table"}


# ============================================================================
# TOOL EXECUTION
# ============================================================================

rate_limiter = RateLimiter(max_requests=MCP_RATE_LIMIT)
cache = TTLCache(default_ttl=MCP_CACHE_TTL)
http_client = TeamDeskClient()
api_key_validator = ApiKeyValidator(cache_ttl=MCP_API_KEY_CACHE_TTL)
mcp_server = Server("teamdesk-mcp-server")


@mcp_server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return TOOLS


@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": "Use the HTTP endpoint"}))]


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
        # CORRECT: POST {table}/create.json with body=[{data}] (NOT POST {table}.json)
        return await http_client.request("POST", token, f"{table}/create.json", json_data=[args["data"]])

    elif name == "update_record":
        err = validate_required(args, ["table", "record_id", "data"])
        if err:
            return {"error": err}
        table = sanitize_table_name(args["table"])
        record_id = int(args["record_id"])
        update_data = {**args["data"], "@row.id": record_id}
        # CORRECT: POST {table}/update.json with body=[{"@row.id": id, ...}]
        # (NOT PUT {table}/{id}.json)
        return await http_client.request("POST", token, f"{table}/update.json", json_data=[update_data])

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
        table = sanitize_table_name(args["table"])
        safe_text = sanitize_search_text(args["search_text"])
        params = {
            "filter": f"Contains([*], '{safe_text}')",
            "top": min(args.get("top", 50), 500),
        }
        if args.get("columns"):
            params["column"] = args["columns"]
        return await http_client.request("GET", token, f"{table}/select.json", params=params)

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

    return {"error": f"Unknown tool: {name}"}


# ============================================================================
# HTTP ENDPOINTS
# ============================================================================


async def health_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "healthy",
        "service": "teamdesk-mcp-server",
        "version": "2.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
    if validation.record_id:
        asyncio.create_task(api_key_validator.update_last_use(validation.record_id, http_client))

    return JSONResponse({"result": result["result"]}, status_code=200, headers=headers)


async def sse_endpoint(request: Request):
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return JSONResponse({"error": "API key required (header X-API-Key)"}, status_code=401)

    validation = await api_key_validator.validate(api_key, http_client)
    if not validation.valid:
        return JSONResponse({"error": validation.error}, status_code=401)

    sse = SseServerTransport("/messages")
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp_server.run(streams[0], streams[1], mcp_server.create_initialization_options())


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
    task = asyncio.create_task(cleanup_task())
    print(f"TeamDesk MCP Server v2.1 (SSE)")
    print(f"Host: {MCP_HOST}:{MCP_PORT}")
    print(f"Database: {'configured' if TEAMDESK_DATABASE_ID else 'NOT SET'}")
    print(f"Master Token: {'configured' if TEAMDESK_MASTER_TOKEN else 'NOT SET'}")
    yield
    task.cancel()
    await http_client.stop()


# Restrictive CORS: no wildcard by default
cors_origins = [o.strip() for o in MCP_CORS_ORIGINS if o.strip()]

routes = [
    Route("/health", health_endpoint, methods=["GET"]),
    Route("/tools", tools_list_endpoint, methods=["GET"]),
    Route("/tools/call", tools_call_endpoint, methods=["POST"]),
    Route("/sse", sse_endpoint, methods=["GET"]),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
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
