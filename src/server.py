"""
Teamdesk MCP Server v2
Servidor MCP para integração com Teamdesk API
Com autenticação, rate limiting, cache e performance otimizada
"""

import os
import json
import time
import asyncio
import hashlib
from typing import Any, Optional
from collections import defaultdict
from datetime import datetime
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
)
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

# Carregar variáveis de ambiente
load_dotenv()

# Configurações
TEAMDESK_DATABASE_ID = os.getenv("TEAMDESK_DATABASE_ID", "")
TEAMDESK_MASTER_TOKEN = os.getenv("TEAMDESK_MASTER_TOKEN", "")
TEAMDESK_API_KEYS_TABLE = os.getenv("TEAMDESK_API_KEYS_TABLE", "API-Keys")
MCP_RATE_LIMIT = int(os.getenv("MCP_RATE_LIMIT", "100"))
MCP_CACHE_TTL = int(os.getenv("MCP_CACHE_TTL", "300"))
MCP_API_KEY_CACHE_TTL = int(os.getenv("MCP_API_KEY_CACHE_TTL", "60"))  # Cache de validação de API Key
MCP_CORS_ORIGINS = os.getenv("MCP_CORS_ORIGINS", "*").split(",")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8080"))
MCP_MAX_PAYLOAD_SIZE = int(os.getenv("MCP_MAX_PAYLOAD_SIZE", "1048576"))  # 1MB

# URL base da API TeamDesk
TEAMDESK_API_BASE = "https://www.teamdesk.net/secure/api/v2"


# ============================================================================
# RATE LIMITER - Implementação em memória
# ============================================================================

class RateLimiter:
    """Rate limiter em memória por IP/cliente."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_id: str) -> tuple[bool, int]:
        """
        Verifica se o cliente pode fazer mais requisições.
        Retorna (permitido, requisições_restantes).
        """
        async with self._lock:
            now = time.time()
            window_start = now - self.window_seconds

            # Limpar requisições antigas
            self.requests[client_id] = [
                t for t in self.requests[client_id] if t > window_start
            ]

            current_count = len(self.requests[client_id])

            if current_count >= self.max_requests:
                return False, 0

            self.requests[client_id].append(now)
            return True, self.max_requests - current_count - 1

    async def cleanup(self):
        """Remove entradas antigas periodicamente."""
        async with self._lock:
            now = time.time()
            window_start = now - self.window_seconds

            empty_clients = []
            for client_id, timestamps in self.requests.items():
                self.requests[client_id] = [t for t in timestamps if t > window_start]
                if not self.requests[client_id]:
                    empty_clients.append(client_id)

            for client_id in empty_clients:
                del self.requests[client_id]


# ============================================================================
# CACHE - Implementação com TTL
# ============================================================================

class CacheEntry:
    """Entrada de cache com TTL."""

    def __init__(self, value: Any, ttl_seconds: int):
        self.value = value
        self.expires_at = time.time() + ttl_seconds


class TTLCache:
    """Cache em memória com TTL."""

    def __init__(self, default_ttl: int = 300):
        self.default_ttl = default_ttl
        self.cache: dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    def _make_key(self, token: str, operation: str, params: dict) -> str:
        """Gera chave de cache única por token+operação+parâmetros."""
        params_str = json.dumps(params, sort_keys=True)
        key_data = f"{token}:{operation}:{params_str}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    async def get(self, token: str, operation: str, params: dict) -> tuple[Any, bool]:
        """
        Obtém valor do cache.
        Retorna (valor, hit) onde hit indica se encontrou no cache.
        """
        async with self._lock:
            key = self._make_key(token, operation, params)
            entry = self.cache.get(key)

            if entry is None:
                return None, False

            if time.time() > entry.expires_at:
                del self.cache[key]
                return None, False

            return entry.value, True

    async def set(self, token: str, operation: str, params: dict, value: Any, ttl: Optional[int] = None):
        """Armazena valor no cache."""
        async with self._lock:
            key = self._make_key(token, operation, params)
            self.cache[key] = CacheEntry(value, ttl or self.default_ttl)

    async def cleanup(self):
        """Remove entradas expiradas."""
        async with self._lock:
            now = time.time()
            expired = [k for k, v in self.cache.items() if now > v.expires_at]
            for key in expired:
                del self.cache[key]


# ============================================================================
# VALIDADOR DE API KEYS
# ============================================================================

class ApiKeyValidationResult:
    """Resultado da validação de uma API Key."""

    def __init__(
        self,
        valid: bool,
        token: Optional[str] = None,
        user_name: Optional[str] = None,
        record_id: Optional[int] = None,
        error: Optional[str] = None,
    ):
        self.valid = valid
        self.token = token
        self.user_name = user_name
        self.record_id = record_id
        self.error = error


class ApiKeyValidator:
    """Validador de API Keys usando a tabela do TeamDesk."""

    def __init__(self, cache_ttl: int = 60):
        self.cache: dict[str, tuple[ApiKeyValidationResult, float]] = {}
        self.cache_ttl = cache_ttl
        self._lock = asyncio.Lock()

    async def validate(self, api_key: str, http_client: "TeamDeskClient") -> ApiKeyValidationResult:
        """
        Valida uma API Key consultando a tabela API-Keys do TeamDesk.
        Retorna o token do usuário se válida.
        """
        # Verificar cache
        async with self._lock:
            if api_key in self.cache:
                result, expires_at = self.cache[api_key]
                if time.time() < expires_at:
                    return result
                else:
                    del self.cache[api_key]

        # Consultar TeamDesk usando o token master
        if not TEAMDESK_MASTER_TOKEN:
            return ApiKeyValidationResult(
                valid=False,
                error="Servidor não configurado: TEAMDESK_MASTER_TOKEN ausente"
            )

        # Buscar na tabela API-Keys
        filter_query = f"[Key]='{api_key}'"
        response = await http_client.request(
            method="GET",
            token=TEAMDESK_MASTER_TOKEN,
            endpoint=f"{TEAMDESK_API_KEYS_TABLE}/select.json",
            params={
                "filter": filter_query,
                "column": ["Key", "Token", "Ativo", "Nome", "@Row ID"],
            },
        )

        # Verificar erro na resposta
        if "error" in response:
            return ApiKeyValidationResult(
                valid=False,
                error=f"Erro ao validar API Key: {response['error']}"
            )

        # Verificar se encontrou registro
        records = response if isinstance(response, list) else response.get("data", [])
        if not records:
            result = ApiKeyValidationResult(
                valid=False,
                error="API Key não encontrada"
            )
            # Cachear resultado negativo por menos tempo
            async with self._lock:
                self.cache[api_key] = (result, time.time() + 10)
            return result

        record = records[0]

        # Verificar se está ativa
        ativo = record.get("Ativo", "")
        if ativo not in ("Sim", "Yes", True, "true", "1", 1):
            result = ApiKeyValidationResult(
                valid=False,
                error="API Key desativada"
            )
            async with self._lock:
                self.cache[api_key] = (result, time.time() + 10)
            return result

        # Obter token do usuário
        user_token = record.get("Token", "")
        if not user_token:
            return ApiKeyValidationResult(
                valid=False,
                error="Token do usuário não configurado na API Key"
            )

        # Criar resultado válido
        result = ApiKeyValidationResult(
            valid=True,
            token=user_token,
            user_name=record.get("Nome", ""),
            record_id=record.get("@Row ID"),
        )

        # Cachear resultado
        async with self._lock:
            self.cache[api_key] = (result, time.time() + self.cache_ttl)

        return result

    async def update_last_use(self, record_id: int, http_client: "TeamDeskClient"):
        """Atualiza o campo Ultimo_Uso do registro da API Key."""
        if not record_id or not TEAMDESK_MASTER_TOKEN:
            return

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        await http_client.request(
            method="PUT",
            token=TEAMDESK_MASTER_TOKEN,
            endpoint=f"{TEAMDESK_API_KEYS_TABLE}/{record_id}.json",
            json_data={"Ultimo_Uso": now},
            retries=1,  # Não retentar para não atrasar a resposta
        )

    async def cleanup(self):
        """Remove entradas expiradas do cache."""
        async with self._lock:
            now = time.time()
            expired = [k for k, (_, exp) in self.cache.items() if now > exp]
            for key in expired:
                del self.cache[key]


# ============================================================================
# CLIENTE HTTP PERSISTENTE
# ============================================================================

class TeamDeskClient:
    """Cliente HTTP persistente para TeamDesk API."""

    def __init__(self):
        self.client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Inicializa o cliente HTTP com connection pooling."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                    keepalive_expiry=30.0,
                ),
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=30.0,
                    write=10.0,
                    pool=5.0,
                ),
            )

    async def stop(self):
        """Fecha o cliente HTTP."""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def request(
        self,
        method: str,
        token: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        retries: int = 3,
    ) -> dict:
        """
        Faz requisição à API TeamDesk com retry automático.
        """
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
                response = await self.client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                )

                if response.status_code == 401:
                    return {"error": "Token inválido ou expirado", "status": 401}

                if response.status_code == 403:
                    return {"error": "Sem permissão para esta operação", "status": 403}

                if response.status_code == 404:
                    return {"error": "Recurso não encontrado", "status": 404}

                if response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"Server error: {response.status_code}",
                        request=response.request,
                        response=response,
                    )

                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        return {"error": error_data, "status": response.status_code}
                    except Exception:
                        return {"error": response.text, "status": response.status_code}

                try:
                    return response.json()
                except Exception:
                    return {"data": response.text}

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPStatusError) as e:
                last_error = e
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue

        return {"error": f"Falha após {retries} tentativas: {str(last_error)}", "status": 503}


# ============================================================================
# VALIDAÇÃO DE ENTRADA
# ============================================================================

def sanitize_table_name(name: str) -> str:
    """Sanitiza nome de tabela para prevenir injection."""
    # Remove caracteres perigosos, mantém apenas alfanuméricos, underscore e espaços
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ -")
    return "".join(c for c in name if c in allowed)[:100]


def validate_required_params(params: dict, required: list[str]) -> Optional[str]:
    """Valida se todos os parâmetros obrigatórios estão presentes."""
    missing = [p for p in required if not params.get(p)]
    if missing:
        return f"Parâmetros obrigatórios ausentes: {', '.join(missing)}"
    return None


# ============================================================================
# FERRAMENTAS MCP
# ============================================================================

# Definição das ferramentas disponíveis
TOOLS = [
    Tool(
        name="list_tables",
        description="Lista todas as tabelas disponíveis no banco TeamDesk",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="describe_table",
        description="Descreve a estrutura de uma tabela (colunas, tipos)",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
            },
            "required": ["table"],
        },
    ),
    Tool(
        name="get_records",
        description="Obtém registros de uma tabela com filtros opcionais",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "filter": {
                    "type": "string",
                    "description": "Filtro no formato TeamDesk (ex: [Campo]='valor')",
                },
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de colunas a retornar",
                },
                "top": {
                    "type": "integer",
                    "description": "Número máximo de registros (padrão: 100)",
                },
                "skip": {
                    "type": "integer",
                    "description": "Número de registros a pular (paginação)",
                },
                "sort": {
                    "type": "string",
                    "description": "Coluna para ordenação",
                },
                "desc": {
                    "type": "boolean",
                    "description": "Ordenar em ordem decrescente",
                },
            },
            "required": ["table"],
        },
    ),
    Tool(
        name="get_record",
        description="Obtém um registro específico pelo ID",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "record_id": {
                    "type": "integer",
                    "description": "ID do registro",
                },
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de colunas a retornar",
                },
            },
            "required": ["table", "record_id"],
        },
    ),
    Tool(
        name="create_record",
        description="Cria um novo registro na tabela",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "data": {
                    "type": "object",
                    "description": "Dados do registro (campo: valor)",
                },
            },
            "required": ["table", "data"],
        },
    ),
    Tool(
        name="update_record",
        description="Atualiza um registro existente",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "record_id": {
                    "type": "integer",
                    "description": "ID do registro",
                },
                "data": {
                    "type": "object",
                    "description": "Dados a atualizar (campo: valor)",
                },
            },
            "required": ["table", "record_id", "data"],
        },
    ),
    Tool(
        name="delete_record",
        description="Remove um registro da tabela",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "record_id": {
                    "type": "integer",
                    "description": "ID do registro",
                },
            },
            "required": ["table", "record_id"],
        },
    ),
    Tool(
        name="select_query",
        description="Executa uma query SELECT personalizada",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Query SELECT no formato TeamDesk",
                },
            },
            "required": ["query"],
        },
    ),
    Tool(
        name="upsert_records",
        description="Cria ou atualiza registros em lote (match por coluna)",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "match_column": {
                    "type": "string",
                    "description": "Coluna para match (ex: External_ID)",
                },
                "records": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Lista de registros a criar/atualizar",
                },
            },
            "required": ["table", "match_column", "records"],
        },
    ),
    Tool(
        name="select_from_view",
        description="Consulta dados de uma view específica",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nome da tabela",
                },
                "view": {
                    "type": "string",
                    "description": "Nome da view",
                },
                "top": {
                    "type": "integer",
                    "description": "Número máximo de registros (padrão: 100)",
                },
            },
            "required": ["table", "view"],
        },
    ),
    Tool(
        name="get_attachment_url",
        description="Gera URL para download de anexo",
        inputSchema={
            "type": "object",
            "properties": {
                "field_id": {
                    "type": "string",
                    "description": "ID do campo de anexo",
                },
                "guid": {
                    "type": "string",
                    "description": "GUID do arquivo",
                },
            },
            "required": ["field_id", "guid"],
        },
    ),
]

# Operações que podem ser cacheadas
CACHEABLE_OPERATIONS = {"list_tables", "describe_table"}


# ============================================================================
# SERVIDOR MCP
# ============================================================================

# Instâncias globais
rate_limiter = RateLimiter(max_requests=MCP_RATE_LIMIT, window_seconds=60)
cache = TTLCache(default_ttl=MCP_CACHE_TTL)
http_client = TeamDeskClient()
api_key_validator = ApiKeyValidator(cache_ttl=MCP_API_KEY_CACHE_TTL)

# Servidor MCP
mcp_server = Server("teamdesk-mcp-server")


@mcp_server.list_tools()
async def list_tools() -> list[Tool]:
    """Retorna lista de ferramentas disponíveis."""
    return TOOLS


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Executa uma ferramenta MCP."""
    # Esta função é chamada internamente pelo MCP
    # O token e validações são tratados no endpoint HTTP
    return [TextContent(type="text", text=json.dumps({"error": "Use o endpoint HTTP"}))]


async def execute_tool(token: str, name: str, arguments: dict) -> dict:
    """Executa uma ferramenta com o token do usuário."""

    # Verificar cache para operações de leitura
    cache_hit = False
    if name in CACHEABLE_OPERATIONS:
        cached_result, cache_hit = await cache.get(token, name, arguments)
        if cache_hit:
            return {"result": cached_result, "cache": "HIT"}

    # Executar ferramenta
    result = await _execute_tool_impl(token, name, arguments)

    # Armazenar em cache se for operação cacheável e não houve erro
    if name in CACHEABLE_OPERATIONS and "error" not in result:
        await cache.set(token, name, arguments, result)

    return {"result": result, "cache": "MISS" if name in CACHEABLE_OPERATIONS else "SKIP"}


async def _execute_tool_impl(token: str, name: str, arguments: dict) -> dict:
    """Implementação das ferramentas."""

    if name == "list_tables":
        return await http_client.request("GET", token, "tables.json")

    elif name == "describe_table":
        error = validate_required_params(arguments, ["table"])
        if error:
            return {"error": error}
        table = sanitize_table_name(arguments["table"])
        return await http_client.request("GET", token, f"{table}/columns.json")

    elif name == "get_records":
        error = validate_required_params(arguments, ["table"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        params = {}

        if arguments.get("filter"):
            params["filter"] = arguments["filter"]
        if arguments.get("columns"):
            params["column"] = arguments["columns"]
        if arguments.get("top"):
            params["top"] = min(arguments["top"], 1000)  # Limitar máximo
        if arguments.get("skip"):
            params["skip"] = arguments["skip"]
        if arguments.get("sort"):
            params["sort"] = arguments["sort"]
        if arguments.get("desc"):
            params["desc"] = "true"

        return await http_client.request("GET", token, f"{table}/select.json", params=params)

    elif name == "get_record":
        error = validate_required_params(arguments, ["table", "record_id"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        record_id = int(arguments["record_id"])
        params = {}

        if arguments.get("columns"):
            params["column"] = arguments["columns"]

        return await http_client.request("GET", token, f"{table}/{record_id}.json", params=params)

    elif name == "create_record":
        error = validate_required_params(arguments, ["table", "data"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        return await http_client.request("POST", token, f"{table}.json", json_data=arguments["data"])

    elif name == "update_record":
        error = validate_required_params(arguments, ["table", "record_id", "data"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        record_id = int(arguments["record_id"])
        return await http_client.request("PUT", token, f"{table}/{record_id}.json", json_data=arguments["data"])

    elif name == "delete_record":
        error = validate_required_params(arguments, ["table", "record_id"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        record_id = int(arguments["record_id"])
        return await http_client.request("DELETE", token, f"{table}/{record_id}.json")

    elif name == "select_query":
        error = validate_required_params(arguments, ["query"])
        if error:
            return {"error": error}

        return await http_client.request("POST", token, "select.json", json_data={"query": arguments["query"]})

    elif name == "upsert_records":
        error = validate_required_params(arguments, ["table", "match_column", "records"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        params = {"match": arguments["match_column"]}
        return await http_client.request("POST", token, f"{table}/upsert.json", params=params, json_data=arguments["records"])

    elif name == "select_from_view":
        error = validate_required_params(arguments, ["table", "view"])
        if error:
            return {"error": error}

        table = sanitize_table_name(arguments["table"])
        view = sanitize_table_name(arguments["view"])
        params = {"top": min(arguments.get("top", 100), 1000)}
        return await http_client.request("GET", token, f"{view}/{table}/select.json", params=params)

    elif name == "get_attachment_url":
        error = validate_required_params(arguments, ["field_id", "guid"])
        if error:
            return {"error": error}

        url = f"https://www.teamdesk.net/secure/db/{TEAMDESK_DATABASE_ID}/attachment.aspx?fid={arguments['field_id']}&guid={arguments['guid']}"
        return {"url": url}

    else:
        return {"error": f"Ferramenta desconhecida: {name}"}


# ============================================================================
# ENDPOINTS HTTP
# ============================================================================

async def health_endpoint(request: Request) -> JSONResponse:
    """Endpoint de health check (público)."""
    return JSONResponse({
        "status": "healthy",
        "service": "teamdesk-mcp-server",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    })


async def tools_list_endpoint(request: Request) -> JSONResponse:
    """Lista ferramentas disponíveis."""
    # Extrai token (opcional para listar ferramentas)
    tools_data = [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema,
        }
        for t in TOOLS
    ]
    return JSONResponse({"tools": tools_data})


async def tools_call_endpoint(request: Request) -> Response:
    """Executa uma ferramenta."""

    # Extrair IP do cliente para rate limiting
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    # Verificar rate limit
    allowed, remaining = await rate_limiter.is_allowed(client_ip)
    headers = {
        "X-RateLimit-Limit": str(MCP_RATE_LIMIT),
        "X-RateLimit-Remaining": str(remaining),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    if not allowed:
        return JSONResponse(
            {"error": "Rate limit excedido. Tente novamente em alguns segundos."},
            status_code=429,
            headers=headers,
        )

    # Extrair API Key (header ou query parameter)
    api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if not api_key:
        return JSONResponse(
            {"error": "API Key é obrigatória (header X-API-Key ou query param api_key)"},
            status_code=401,
            headers=headers,
        )

    # Validar API Key usando a tabela do TeamDesk
    validation = await api_key_validator.validate(api_key, http_client)
    if not validation.valid:
        return JSONResponse(
            {"error": validation.error},
            status_code=401,
            headers=headers,
        )

    # Token do usuário validado
    token = validation.token
    headers["X-User"] = validation.user_name or "unknown"

    # Verificar tamanho do payload
    content_length = request.headers.get("Content-Length")
    if content_length and int(content_length) > MCP_MAX_PAYLOAD_SIZE:
        return JSONResponse(
            {"error": f"Payload excede o limite de {MCP_MAX_PAYLOAD_SIZE} bytes"},
            status_code=413,
            headers=headers,
        )

    # Parsear body
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Body inválido. Esperado JSON."},
            status_code=400,
            headers=headers,
        )

    # Validar estrutura
    tool_name = body.get("name")
    arguments = body.get("arguments", {})

    if not tool_name:
        return JSONResponse(
            {"error": "Campo 'name' é obrigatório"},
            status_code=400,
            headers=headers,
        )

    # Verificar se ferramenta existe
    valid_tools = {t.name for t in TOOLS}
    if tool_name not in valid_tools:
        return JSONResponse(
            {"error": f"Ferramenta '{tool_name}' não encontrada. Disponíveis: {', '.join(valid_tools)}"},
            status_code=404,
            headers=headers,
        )

    # Executar ferramenta
    result = await execute_tool(token, tool_name, arguments)

    # Adicionar header de cache
    headers["X-Cache"] = result.get("cache", "SKIP")

    # Verificar se houve erro do TeamDesk
    if isinstance(result.get("result"), dict) and "error" in result["result"]:
        status_code = result["result"].get("status", 400)
        return JSONResponse(
            {"error": result["result"]["error"]},
            status_code=status_code,
            headers=headers,
        )

    # Atualizar Ultimo_Uso da API Key (em background, sem bloquear resposta)
    if validation.record_id:
        asyncio.create_task(
            api_key_validator.update_last_use(validation.record_id, http_client)
        )

    return JSONResponse(
        {"result": result["result"]},
        status_code=200,
        headers=headers,
    )


async def sse_endpoint(request: Request):
    """Endpoint SSE para conexão MCP."""
    # Extrair API Key (header ou query parameter)
    api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if not api_key:
        return JSONResponse(
            {"error": "API Key é obrigatória (header X-API-Key ou query param api_key)"},
            status_code=401,
        )

    # Validar API Key
    validation = await api_key_validator.validate(api_key, http_client)
    if not validation.valid:
        return JSONResponse(
            {"error": validation.error},
            status_code=401,
        )

    # Criar transporte SSE
    sse = SseServerTransport("/messages")

    async with sse.connect_sse(
        request.scope,
        request.receive,
        request._send,
    ) as streams:
        await mcp_server.run(
            streams[0],
            streams[1],
            mcp_server.create_initialization_options(),
        )


# ============================================================================
# LIFECYCLE E APP
# ============================================================================

async def cleanup_task():
    """Tarefa periódica de limpeza."""
    while True:
        await asyncio.sleep(60)
        await rate_limiter.cleanup()
        await cache.cleanup()
        await api_key_validator.cleanup()


@asynccontextmanager
async def lifespan(app):
    """Gerencia lifecycle da aplicação."""
    # Startup
    await http_client.start()
    cleanup = asyncio.create_task(cleanup_task())

    print(f"TeamDesk MCP Server v2 iniciado")
    print(f"Host: {MCP_HOST}:{MCP_PORT}")
    print(f"Rate Limit: {MCP_RATE_LIMIT} req/min")
    print(f"Cache TTL: {MCP_CACHE_TTL}s")
    print(f"API Key Cache TTL: {MCP_API_KEY_CACHE_TTL}s")
    print(f"Database ID: {TEAMDESK_DATABASE_ID}")
    print(f"API Keys Table: {TEAMDESK_API_KEYS_TABLE}")
    print(f"Master Token: {'configurado' if TEAMDESK_MASTER_TOKEN else 'NAO CONFIGURADO!'}")

    yield

    # Shutdown
    cleanup.cancel()
    await http_client.stop()
    print("Servidor encerrado")


# Rotas
routes = [
    Route("/health", health_endpoint, methods=["GET"]),
    Route("/tools", tools_list_endpoint, methods=["GET"]),
    Route("/tools/call", tools_call_endpoint, methods=["POST"]),
    Route("/sse", sse_endpoint, methods=["GET"]),
]

# Middleware
middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=MCP_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Cache", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    ),
]

# Aplicação Starlette
app = Starlette(
    debug=False,
    routes=routes,
    middleware=middleware,
    lifespan=lifespan,
)


def main():
    """Função principal - inicia o servidor."""
    import uvicorn

    if not TEAMDESK_DATABASE_ID:
        print("ERRO: TEAMDESK_DATABASE_ID não configurado")
        print("Configure no arquivo .env ou variável de ambiente")
        return

    if not TEAMDESK_MASTER_TOKEN:
        print("ERRO: TEAMDESK_MASTER_TOKEN não configurado")
        print("Este token é necessário para validar as API Keys dos usuários")
        print("Configure no arquivo .env ou variável de ambiente")
        return

    uvicorn.run(
        app,
        host=MCP_HOST,
        port=MCP_PORT,
        log_level="info",
    )


if __name__ == "__main__":
    main()
