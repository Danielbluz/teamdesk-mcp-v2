"""
TeamDesk MCP Server - FastMCP stdio
Connects any MCP-compatible client (Claude Desktop, Claude Code, etc.)
to the TeamDesk REST API v2.

Usage:
    python server.py
"""

import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from td_query_checker import check_filter, check_columns, check_table_name, check_all, broaden_filter

# Load .env if present
load_dotenv()

# Configuration from environment
# Accept both TEAMDESK_API_TOKEN (installer) and TEAMDESK_TOKEN (legacy)
TEAMDESK_TOKEN = os.getenv("TEAMDESK_API_TOKEN") or os.getenv("TEAMDESK_TOKEN", "")
TEAMDESK_DATABASE_ID = os.getenv("TEAMDESK_DATABASE_ID", "")
TEAMDESK_BASE_URL = "https://www.teamdesk.net/secure/api/v2"

if not TEAMDESK_TOKEN or not TEAMDESK_DATABASE_ID:
    print(
        "ERROR: TEAMDESK_API_TOKEN and TEAMDESK_DATABASE_ID must be set.\n"
        "Run the installer or set environment variables manually.",
        file=sys.stderr,
    )
    sys.exit(1)

# Initialize MCP server
mcp = FastMCP("TeamDesk MCP")


def _sanitize_table_name(name: str) -> str:
    """URL-encode table name to handle accented characters safely."""
    return urllib.parse.quote(name, safe="")


def sanitize_search_text(text: str) -> str:
    """Escape single quotes in search text to prevent filter injection."""
    return text.replace("'", "''")


def _log(msg: str) -> None:
    """Log to stderr (visible in Claude Desktop dev tools, never sent to client)."""
    print(f"[TeamDesk MCP] {msg}", file=sys.stderr, flush=True)


def make_request(
    endpoint: str, method: str = "GET", data: Any = None, max_retries: int = 2
) -> dict:
    """Make a request to the TeamDesk API with retry and logging."""
    url = (
        f"{TEAMDESK_BASE_URL}"
        f"/{TEAMDESK_DATABASE_ID}"
        f"/{endpoint}"
    )

    headers = {
        "Authorization": f"Bearer {TEAMDESK_TOKEN}",
        "Content-Type": "application/json",
    }

    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")

    last_error = None
    for attempt in range(1, max_retries + 1):
        request = urllib.request.Request(
            url, data=req_data, headers=headers, method=method
        )
        t0 = time.time()
        try:
            with urllib.request.urlopen(request, timeout=55) as response:
                body = response.read().decode("utf-8")
                elapsed = time.time() - t0
                _log(f"{method} {endpoint} → {response.status} ({elapsed:.1f}s)")
                return json.loads(body)
        except urllib.error.HTTPError as e:
            elapsed = time.time() - t0
            error_body = e.read().decode("utf-8") if e.fp else str(e)
            _log(f"{method} {endpoint} → HTTP {e.code} ({elapsed:.1f}s) attempt {attempt}/{max_retries}")
            last_error = f"HTTP {e.code}: {error_body}"
            # Don't retry client errors (4xx) — only server/timeout errors
            if 400 <= e.code < 500:
                return {"error": last_error}
        except Exception as e:
            elapsed = time.time() - t0
            _log(f"{method} {endpoint} → {type(e).__name__}: {e} ({elapsed:.1f}s) attempt {attempt}/{max_retries}")
            last_error = str(e)

        if attempt < max_retries:
            wait = 3 * attempt  # 3s, 6s
            _log(f"Retrying in {wait}s...")
            time.sleep(wait)

    return {"error": f"Falha após {max_retries} tentativas: {last_error}"}


# ---------------------------------------------------------------------------
# Resources — static/semi-static data the LLM can read without calling tools
# ---------------------------------------------------------------------------

@mcp.resource("teamdesk://schema")
def resource_schema() -> str:
    """Complete database schema: all tables with their columns and types.
    Loaded once per session, avoids repeated describe_table calls."""
    result = make_request("describe.json")
    if "error" in result:
        return json.dumps({"error": result["error"]})

    tables = result.get("tables", [])
    schema_output = {}
    for table in tables:
        tname = table["recordName"]
        encoded = _sanitize_table_name(tname)
        desc = make_request(f"{encoded}/describe.json")
        if "error" not in desc:
            cols = [
                {"name": c["name"], "type": c.get("type", "?"), "key": c.get("isKey", False)}
                for c in desc.get("columns", [])
            ]
            schema_output[tname] = {
                "id": table["id"],
                "columns": cols,
                "column_count": len(cols),
            }
    return json.dumps(schema_output, indent=2, ensure_ascii=False)


@mcp.resource("teamdesk://gotchas")
def resource_gotchas() -> str:
    """Critical TeamDesk API gotchas that prevent common errors."""
    return json.dumps({
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
            "delete_purge": "Add ?purge=1 to permanently delete without trash.",
        },
        "column_names": {
            "accents_required": "Column names must use exact accents: Geração, Instalação, Irradiação, Potência, Mês.",
            "Sum_vs_plus": "Sum([A],[B],[C]) ignores nulls. [A]+[B]+[C] propagates null.",
            "calculated_field_overwrite": "API writes to Default/Calculate fields overwrite the formula. Write to component columns instead.",
        },
        "endpoints": {
            "select_endpoint": "Use /table/select.json (NOT /table.json — 405 error)",
            "document_no_json": "Document endpoint: /table/doc/document (NO .json suffix)",
            "sort_syntax": "Sort: 'Column//DESC' (double slash, not dash)",
        },
    }, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Prompts — pre-defined templates that guide the LLM
# ---------------------------------------------------------------------------

@mcp.prompt()
def consulta_geracao(usina: str, periodo: str = "último mês") -> str:
    """Template para consultar geração de energia de uma usina."""
    return f"""Consulte a geração de energia da usina "{usina}" no período "{periodo}".

Passos recomendados:
1. Use aggregate_query na tabela "Geracao_Dia" com measure_column="Geracao dia (kWh)", measure_function="SUM", group_column="Data", group_function="MM"
2. Filtre por Contains([Unidade Geradora], '{usina}') e o período de datas
3. Compare com o P90 esperado na tabela "Geração Mensal" (coluna "Geracao P90 (kWh)")
4. Calcule o Performance Ratio: (Geração Real / P90) × 100

Formate os números no padrão brasileiro (1.234,56 kWh) e mostre em lista compacta."""


@mcp.prompt()
def auditoria_tabela(tabela: str) -> str:
    """Template para auditar qualidade de dados de uma tabela."""
    return f"""Audite a qualidade dos dados na tabela "{tabela}".

Passos:
1. Use describe_table para ver a estrutura (colunas, tipos)
2. Use count_records para saber o total de registros
3. Para cada coluna importante, use aggregate_query com COUNT para verificar preenchimento
4. Use get_records com filtros específicos para detectar:
   - Registros sem campos obrigatórios preenchidos
   - Valores fora do esperado (use MIN/MAX via aggregate_query)
   - Possíveis duplicatas (group_column com COUNT > 1)

Reporte: total de registros, % campos vazios, anomalias encontradas."""


@mcp.prompt()
def debug_filter(tabela: str, filtro: str) -> str:
    """Template para depurar um filtro que não retorna resultados."""
    return f"""O filtro abaixo não está retornando resultados na tabela "{tabela}":
```
{filtro}
```

Passos de diagnóstico:
1. Use smart_query (que auto-corrige erros comuns: acentos, datas, LIKE→Contains, AND→and)
2. Se ainda 0 resultados, o smart_query tentará broadening automático
3. Use count_records sem filtro para confirmar que a tabela tem dados
4. Use describe_table para verificar os nomes exatos das colunas
5. Teste cada condição do filtro separadamente para identificar qual falha

Gotchas comuns:
- Acentos errados: Geracao→Geração, Instalacao→Instalação
- Datas sem hashes: '2026-01-01' deve ser #2026-01-01#
- LIKE não existe: use Contains([Campo], 'valor')
- Operadores maiúsculos: AND/OR devem ser and/or"""


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_tables() -> str:
    """
    List all tables in the TeamDesk database.
    Returns table names and IDs.
    """
    result = make_request("describe.json")

    if "error" in result:
        return f"Error: {result['error']}"

    tables = []
    for table in result.get("tables", []):
        tables.append(
            {
                "id": table["id"],
                "name": table["recordName"],
                "name_plural": table["recordsName"],
            }
        )

    return json.dumps(tables, indent=2, ensure_ascii=False)


@mcp.tool()
def describe_table(table_name: str) -> str:
    """
    Describe the structure of a table (columns, types, properties).

    Args:
        table_name: Table name (e.g. "Usina Solar", "Cliente", "Faturamento")
    """
    encoded = _sanitize_table_name(table_name)
    result = make_request(f"{encoded}/describe.json")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def get_records(
    table_name: str,
    columns: str = None,
    filter_expr: str = None,
    sort: str = None,
    top: int = 100,
    skip: int = 0,
) -> str:
    """
    Query records from a TeamDesk table.

    Args:
        table_name: Table name (e.g. "Usina Solar", "Cliente")
        columns: Columns to return, comma-separated (optional, returns all if empty)
        filter_expr: TeamDesk filter expression (e.g. "[Status] = 'Ativo'")
        sort: Sort expression. Use "Column" for ascending or "Column//DESC" for descending.
        top: Maximum number of records (default: 100, max: 500)
        skip: Records to skip for pagination (default: 0)
    """
    encoded = _sanitize_table_name(table_name)

    params = {"top": min(top, 500), "skip": skip}

    if columns:
        params["column"] = columns.split(",")
    if filter_expr:
        params["filter"] = filter_expr
    if sort:
        params["sort"] = sort

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/select.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def get_record(table_name: str, record_id: int, columns: str = None) -> str:
    """
    Retrieve a specific record by ID.

    Args:
        table_name: Table name
        record_id: Record ID
        columns: Columns to return, comma-separated (optional)
    """
    encoded = _sanitize_table_name(table_name)

    params = {"id": record_id}
    if columns:
        params["column"] = columns.split(",")

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/retrieve.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def select_view(
    table_name: str, view_name: str, top: int = 100, skip: int = 0
) -> str:
    """
    Query records from a specific View in TeamDesk.

    Args:
        table_name: Table name
        view_name: View name (e.g. "Default View", "Ativos")
        top: Maximum number of records (default: 100)
        skip: Records to skip for pagination
    """
    encoded_table = _sanitize_table_name(table_name)
    encoded_view = _sanitize_table_name(view_name)

    params = {"top": min(top, 500), "skip": skip}
    query_string = urllib.parse.urlencode(params)

    result = make_request(
        f"{encoded_table}/{encoded_view}/select.json?{query_string}"
    )

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def create_record(table_name: str, data: str, suppress_triggers: bool = False) -> str:
    """
    Create a new record in a table.

    Args:
        table_name: Table name
        data: Record data as JSON string (e.g. '{"Nome": "Test", "Status": "Ativo"}')
        suppress_triggers: If true, suppress workflow triggers/notifications (default: false)
    """
    encoded = _sanitize_table_name(table_name)

    try:
        record_data = json.loads(data)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON - {e}"

    endpoint = f"{encoded}/create.json"
    if suppress_triggers:
        endpoint += "?workflow=0"
    result = make_request(endpoint, method="POST", data=[record_data])

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def update_record(table_name: str, record_id: int, data: str, suppress_triggers: bool = False) -> str:
    """
    Update an existing record.

    Args:
        table_name: Table name
        record_id: Record ID to update
        data: Data to update as JSON string (e.g. '{"Status": "Inativo"}')
        suppress_triggers: If true, suppress workflow triggers/notifications (default: false)
    """
    encoded = _sanitize_table_name(table_name)

    try:
        record_data = json.loads(data)
        record_data["@row.id"] = record_id
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON - {e}"

    endpoint = f"{encoded}/update.json"
    if suppress_triggers:
        endpoint += "?workflow=0"
    result = make_request(endpoint, method="POST", data=[record_data])

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def delete_record(table_name: str, record_id: int) -> str:
    """
    Delete a record from a table.

    Args:
        table_name: Table name
        record_id: Record ID to delete
    """
    encoded = _sanitize_table_name(table_name)
    result = make_request(f"{encoded}/delete.json?id={record_id}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps({"success": True, "deleted_id": record_id}, indent=2)


@mcp.tool()
def search_records(
    table_name: str,
    search_text: str,
    search_columns: str = None,
    columns: str = None,
    top: int = 50,
) -> str:
    """
    Search records containing the specified text in a single table.
    Uses schema-based search across text columns (NOT broken [*] wildcard).

    Args:
        table_name: Table name
        search_text: Text to search for
        search_columns: Columns to search IN, comma-separated (optional).
            If omitted, auto-detects text columns via describe.json.
        columns: Columns to return in the result, comma-separated (optional)
        top: Maximum results (default: 50)
    """
    encoded = _sanitize_table_name(table_name)
    safe_text = sanitize_search_text(search_text)

    # Build schema-based filter instead of broken Contains([*], ...)
    search_filter = _build_search_filter(table_name, safe_text)
    if not search_filter:
        return json.dumps({"error": f"No searchable text columns found in table '{table_name}'"})

    params = {"top": min(top, 500), "filter": search_filter}
    if columns:
        params["column"] = columns.split(",")

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/select.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def upsert_records(table_name: str, match_column: str, data: str, suppress_triggers: bool = False) -> str:
    """
    Insert or update records (upsert) in a table.
    If a record with the match_column value exists, it updates. Otherwise, it creates.

    Args:
        table_name: Table name
        match_column: Column used for matching (must be marked as Unique in TeamDesk)
        data: JSON array of records (e.g. '[{"Nome": "X", "Valor": 1}]')
        suppress_triggers: If true, suppress workflow triggers/notifications (default: false)
    """
    encoded = _sanitize_table_name(table_name)
    encoded_match = urllib.parse.quote(match_column, safe="")

    try:
        records = json.loads(data)
        if not isinstance(records, list):
            records = [records]
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON - {e}"

    endpoint = f"{encoded}/upsert.json?match={encoded_match}"
    if suppress_triggers:
        endpoint += "&workflow=0"
    result = make_request(
        endpoint,
        method="POST",
        data=records,
    )

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def gerar_documento(
    table_name: str,
    document_name: str,
    record_id: int,
    output_path: str = None,
) -> str:
    """
    Generate a Word document (DOCX) from a TeamDesk Documents template.
    Uses the Mail Merge API to fill MERGEFIELDs with record data.

    Args:
        table_name: Table name (e.g. "Relatorio O&M")
        document_name: Document/template name in TeamDesk
        record_id: Record ID to fill the template with
        output_path: File path to save (optional, defaults to ~/Downloads)
    """
    encoded_table = _sanitize_table_name(table_name)
    encoded_doc = urllib.parse.quote(document_name, safe="")

    url = (
        f"{TEAMDESK_BASE_URL}/{TEAMDESK_DATABASE_ID}"
        f"/{encoded_table}/{encoded_doc}/document?id={record_id}"
    )

    headers = {
        "Authorization": f"Bearer {TEAMDESK_TOKEN}",
    }

    request = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read()
            content_type = response.headers.get("Content-Type", "")

            if "application/json" in content_type:
                error_data = json.loads(content.decode("utf-8"))
                return f"Error: {json.dumps(error_data, ensure_ascii=False)}"

            if not output_path:
                downloads = os.path.expanduser("~/Downloads")
                os.makedirs(downloads, exist_ok=True)
                output_path = os.path.join(
                    downloads, f"documento_{record_id}.docx"
                )

            with open(output_path, "wb") as f:
                f.write(content)

            return json.dumps(
                {
                    "success": True,
                    "record_id": record_id,
                    "output_path": output_path,
                    "size_bytes": len(content),
                },
                indent=2,
                ensure_ascii=False,
            )

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else str(e)
        return f"HTTP Error {e.code}: {error_body}"
    except Exception as e:
        return f"Error: {str(e)}"


# ---------------------------------------------------------------------------
# Schema cache (avoids repeated describe_table calls)
# ---------------------------------------------------------------------------
_schema_cache: dict[str, dict] = {}
_table_list_cache: Optional[list[str]] = None


def _get_table_list() -> list[str]:
    """Get and cache list of all table names."""
    global _table_list_cache
    if _table_list_cache is not None:
        return _table_list_cache
    result = make_request("describe.json")
    if "error" not in result:
        _table_list_cache = [t["recordName"] for t in result.get("tables", [])]
        return _table_list_cache
    return []


def _get_schema(table_name: str) -> Optional[dict]:
    """Get and cache table schema for validation."""
    if table_name in _schema_cache:
        return _schema_cache[table_name]
    encoded = _sanitize_table_name(table_name)
    result = make_request(f"{encoded}/describe.json")
    if "error" not in result:
        _schema_cache[table_name] = result
        return result
    return None


@mcp.tool()
def smart_query(
    table_name: str,
    filter_expr: str = None,
    columns: str = None,
    sort: str = None,
    top: int = 100,
    skip: int = 0,
) -> str:
    """
    Query TeamDesk with automatic validation and correction of common mistakes.
    Fixes accent errors in column names, date formats, filter syntax (LIKE→Contains),
    and logical operators (AND→and). Use this instead of get_records for safer queries.

    Args:
        table_name: Table name (e.g. "Usina Solar", "Geracao Mensal", "CUSD")
        filter_expr: Filter expression (e.g. "[Status] = 'Ativo'", "Contains([Nome], 'Paracatu')")
        columns: Columns to return, comma-separated (optional)
        sort: Sort expression (e.g. "Data//DESC")
        top: Maximum records (default: 100, max: 500)
        skip: Records to skip for pagination
    """
    corrections_log = []

    # 1. Check and fix table name
    table_check = check_table_name(table_name)
    if table_check["issues"]:
        corrections_log.extend(
            f"Tabela: {i['message']}" for i in table_check["issues"]
        )
    resolved_table = table_check["corrected"]

    # 2. Get schema for column validation
    schema = _get_schema(resolved_table)

    # 3. Check and fix filter
    resolved_filter = filter_expr
    if filter_expr:
        filter_check = check_filter(filter_expr, schema)
        if filter_check["issues"]:
            corrections_log.extend(
                f"Filtro: {i['message']}" for i in filter_check["issues"]
            )
        resolved_filter = filter_check["corrected"]

    # 4. Check and fix columns
    resolved_columns = columns
    if columns:
        col_list = [c.strip() for c in columns.split(",")]
        col_check = check_columns(col_list, schema)
        if col_check["issues"]:
            corrections_log.extend(
                f"Coluna: {i['message']}" for i in col_check["issues"]
            )
        resolved_columns = ",".join(col_check["corrected"])

    # 5. Execute the corrected query
    encoded = _sanitize_table_name(resolved_table)
    params = {"top": min(top, 500), "skip": skip}

    if resolved_columns:
        params["column"] = resolved_columns.split(",")
    if resolved_filter:
        params["filter"] = resolved_filter
    if sort:
        params["sort"] = sort

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/select.json?{query_string}")

    # 6. Handle errors
    if "error" in result:
        error_msg = result["error"]
        output = {
            "error": error_msg,
            "query_used": {
                "table": resolved_table,
                "filter": resolved_filter,
                "columns": resolved_columns,
            },
        }
        if corrections_log:
            output["corrections_applied"] = corrections_log
        return json.dumps(output, indent=2, ensure_ascii=False)

    # 7. Self-correction loop: if 0 results and filter exists, try broadening
    records = result if isinstance(result, list) else result.get("records", result)
    record_count = len(records) if isinstance(records, list) else 0

    if record_count == 0 and resolved_filter:
        suggestions = broaden_filter(resolved_filter)
        for suggestion in suggestions:
            retry_params = {"top": 5 if suggestion["is_diagnostic"] else min(top, 500), "skip": 0}
            if suggestion["filter"]:
                retry_params["filter"] = suggestion["filter"]
            if resolved_columns:
                retry_params["column"] = resolved_columns.split(",")
            if sort:
                retry_params["sort"] = sort

            retry_qs = urllib.parse.urlencode(retry_params, doseq=True)
            retry_result = make_request(f"{encoded}/select.json?{retry_qs}")

            if "error" in retry_result:
                continue

            retry_records = retry_result if isinstance(retry_result, list) else retry_result.get("records", retry_result)
            retry_count = len(retry_records) if isinstance(retry_records, list) else 0

            if retry_count > 0:
                corrections_log.append(f"Self-correction: {suggestion['description']}")
                if suggestion["is_diagnostic"]:
                    # Diagnostic: table has data but original filter is too narrow
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
                    # Non-diagnostic: return the broader results
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
                return json.dumps(output, indent=2, ensure_ascii=False)

    # 8. Build response with metadata
    output = {"records": records, "count": record_count}

    if corrections_log:
        output["_corrections"] = corrections_log
        output["_note"] = "Query foi corrigida automaticamente antes da execução"

    return json.dumps(output, indent=2, ensure_ascii=False)


_SEARCHABLE_TYPES = {"Text", "Multiline", "Link", "Email", "Phone", "URL"}
_MAX_SEARCH_COLUMNS = 10


def _build_search_filter(table_name: str, safe_text: str) -> Optional[str]:
    """Build a Contains() OR filter using real text columns from schema."""
    schema = _get_schema(table_name)
    if not schema:
        return None
    text_cols = [
        c["name"] for c in schema.get("columns", [])
        if c.get("type") in _SEARCHABLE_TYPES
    ][:_MAX_SEARCH_COLUMNS]
    if not text_cols:
        return None
    parts = [f"Contains([{col}], '{safe_text}')" for col in text_cols]
    return " or ".join(parts)


@mcp.tool()
def global_search(
    search_text: str,
    tables: str = None,
    top_per_table: int = 5,
) -> str:
    """
    Search for text across ALL TeamDesk tables (or specific ones).
    Returns results grouped by table. Builds Contains() filters using
    real text columns from each table's schema.

    Args:
        search_text: Text to search for (e.g. "Paracatu", "3014576923")
        tables: Comma-separated table names to search (optional, searches all if empty)
        top_per_table: Max results per table (default: 5)
    """
    if not search_text or not search_text.strip():
        return json.dumps({"error": "search_text is required"})

    safe_text = sanitize_search_text(search_text.strip())

    # Determine which tables to search
    if tables:
        table_names = [t.strip() for t in tables.split(",") if t.strip()]
    else:
        table_names = _get_table_list()
        if not table_names:
            return json.dumps({"error": "Could not retrieve table list"})

    results = {}
    errors = {}
    skipped = []

    for table_name in table_names:
        search_filter = _build_search_filter(table_name, safe_text)
        if not search_filter:
            skipped.append(table_name)
            continue

        encoded = _sanitize_table_name(table_name)
        params = {
            "filter": search_filter,
            "top": min(top_per_table, 50),
        }
        query_string = urllib.parse.urlencode(params, doseq=True)

        try:
            result = make_request(f"{encoded}/select.json?{query_string}")
        except Exception as e:
            errors[table_name] = str(e)
            continue

        if "error" in result:
            errors[table_name] = result["error"]
            continue

        records = result if isinstance(result, list) else result.get("records", result)
        record_count = len(records) if isinstance(records, list) else 0

        if record_count > 0:
            results[table_name] = {
                "count": record_count,
                "records": records,
            }

    output = {
        "search_text": search_text,
        "tables_searched": len(table_names) - len(skipped),
        "tables_with_results": len(results),
        "results": results,
    }
    if errors:
        output["errors"] = errors

    return json.dumps(output, indent=2, ensure_ascii=False)


@mcp.tool()
def aggregate_query(
    table_name: str,
    measure_column: str,
    measure_function: str = "SUM",
    group_column: str = None,
    group_function: str = None,
    filter_expr: str = None,
    top: int = 500,
) -> str:
    """
    Run aggregation queries (SUM, AVG, COUNT, MIN, MAX) directly on TeamDesk.
    Much more efficient than fetching all records — returns only aggregated results.

    Args:
        table_name: Table name (e.g. "Geracao_Dia", "Geração Mensal")
        measure_column: Column to aggregate (e.g. "Geracao dia (kWh)", "Valor a pagar (R$)")
        measure_function: Aggregation function: SUM, COUNT, AVG, MIN, MAX, STDEV, VAR (default: SUM)
        group_column: Column to group by (optional, e.g. "Unidade Geradora", "Data")
        group_function: Grouping function: EQ (exact), MM (month), YY (year), DD (day), QQ (quarter), HH (hour), FW (first word). For numeric: 1, 10, 100, 1K. (optional, default: EQ)
        filter_expr: Filter expression (optional)
        top: Maximum groups to return (default: 500)
    """
    # Validate table name
    table_check = check_table_name(table_name)
    resolved_table = table_check["corrected"]
    encoded = _sanitize_table_name(resolved_table)

    # Build column params with aggregation suffixes
    columns = []
    if group_column:
        gf = group_function or "EQ"
        columns.append(f"{group_column}//{gf}")
    mf = measure_function.upper()
    if mf not in ("SUM", "COUNT", "AVG", "MIN", "MAX", "STDEV", "STDEVP", "VAR", "VARP"):
        return json.dumps({"error": f"Invalid measure_function: {mf}. Use SUM, COUNT, AVG, MIN, MAX, STDEV, VAR."})
    columns.append(f"{measure_column}//{mf}")

    params = {"column": columns, "top": min(top, 500)}
    if filter_expr:
        filter_check = check_filter(filter_expr, _get_schema(resolved_table))
        params["filter"] = filter_check["corrected"]

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/select.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def count_records(table_name: str, filter_expr: str = None) -> str:
    """
    Count records in a table without returning data. Much faster and lighter than fetching records.

    Args:
        table_name: Table name
        filter_expr: Filter expression (optional)
    """
    table_check = check_table_name(table_name)
    resolved_table = table_check["corrected"]
    encoded = _sanitize_table_name(resolved_table)

    # Get key column from schema for COUNT aggregation
    schema = _get_schema(resolved_table)
    key_col = None
    if schema:
        for col in schema.get("columns", []):
            if col.get("isKey"):
                key_col = col["name"]
                break
    if not key_col:
        key_col = "@row.id"

    params = {"column": [f"{key_col}//COUNT"], "top": 1}
    if filter_expr:
        filter_check = check_filter(filter_expr, schema)
        params["filter"] = filter_check["corrected"]

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/select.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    # Extract count from aggregation result
    records = result if isinstance(result, list) else result.get("records", result)
    count = 0
    if isinstance(records, list) and records:
        # The aggregation result has the count in the first record
        first = records[0]
        for v in first.values():
            if isinstance(v, (int, float)):
                count = int(v)
                break

    return json.dumps({"table": resolved_table, "count": count, "filter": filter_expr}, indent=2, ensure_ascii=False)


@mcp.tool()
def batch_delete(
    table_name: str,
    record_ids: str,
    purge: bool = False,
    suppress_triggers: bool = False,
) -> str:
    """
    Delete multiple records at once.

    Args:
        table_name: Table name
        record_ids: Comma-separated record IDs (e.g. "123,456,789")
        purge: If true, permanently delete without trash (default: false)
        suppress_triggers: If true, suppress workflow triggers (default: false)
    """
    encoded = _sanitize_table_name(table_name)

    ids = [int(x.strip()) for x in record_ids.split(",") if x.strip()]
    if not ids:
        return json.dumps({"error": "No valid record IDs provided"})
    if len(ids) > 500:
        return json.dumps({"error": "Maximum 500 records per batch delete"})

    # Build query with multiple id params
    params = [("id", rid) for rid in ids]
    if purge:
        params.append(("purge", 1))
    if suppress_triggers:
        params.append(("workflow", 0))

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/delete.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps({"success": True, "deleted_ids": ids, "count": len(ids)}, indent=2)


@mcp.tool()
def get_changes(
    table_name: str,
    since: str,
    until: str = None,
    change_type: str = "updated",
) -> str:
    """
    Get records that were modified or deleted in a time range.
    Useful for incremental sync — only fetch what changed since last run.

    Args:
        table_name: Table name
        since: Start datetime in ISO 8601 format (e.g. "2026-03-01T00:00:00")
        until: End datetime (optional, defaults to now)
        change_type: "updated" for modified records, "deleted" for deleted records (default: "updated")
    """
    table_check = check_table_name(table_name)
    resolved_table = table_check["corrected"]
    encoded = _sanitize_table_name(resolved_table)

    if change_type not in ("updated", "deleted"):
        return json.dumps({"error": "change_type must be 'updated' or 'deleted'"})

    params = {"from": since}
    if until:
        params["to"] = until

    query_string = urllib.parse.urlencode(params)
    result = make_request(f"{encoded}/{change_type}.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    records = result if isinstance(result, list) else result.get("records", result)
    record_count = len(records) if isinstance(records, list) else 0

    return json.dumps({
        "table": resolved_table,
        "change_type": change_type,
        "since": since,
        "until": until,
        "count": record_count,
        "records": records,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def list_views(table_name: str) -> str:
    """
    List all available views for a table.

    Args:
        table_name: Table name
    """
    table_check = check_table_name(table_name)
    resolved_table = table_check["corrected"]
    schema = _get_schema(resolved_table)

    if not schema:
        return json.dumps({"error": f"Could not get schema for '{resolved_table}'"})

    views = schema.get("views", [])
    return json.dumps({
        "table": resolved_table,
        "views": [{"name": v.get("name"), "type": v.get("type", "?"), "id": v.get("id")} for v in views],
        "count": len(views),
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def relationship_map(table_name: str = None) -> str:
    """
    Show relationships between tables (which tables reference which).
    If table_name is provided, shows only that table's relationships.
    Otherwise shows all relationships (may be slow on first call).

    Args:
        table_name: Specific table to map (optional, maps all if empty)
    """
    if table_name:
        tables = [check_table_name(table_name)["corrected"]]
    else:
        tables = _get_table_list()
        if not tables:
            return json.dumps({"error": "Could not get table list"})

    relationships = []
    for tbl in tables:
        schema = _get_schema(tbl)
        if not schema:
            continue
        for col in schema.get("columns", []):
            col_type = col.get("type", "")
            # Reference/Lookup columns indicate relationships
            if col_type in ("Link", "Reference", "Lookup", "Summary"):
                rel = {
                    "from_table": tbl,
                    "column": col["name"],
                    "type": col_type,
                }
                # Extract target table from column properties if available
                if col.get("relatedTable"):
                    rel["to_table"] = col["relatedTable"]
                elif col.get("options", {}).get("table"):
                    rel["to_table"] = col["options"]["table"]
                relationships.append(rel)

    # Generate Mermaid diagram
    mermaid_lines = ["graph LR"]
    seen = set()
    for r in relationships:
        if r.get("to_table") and r["type"] in ("Link", "Reference"):
            key = f"{r['from_table']}-->{r['to_table']}"
            if key not in seen:
                safe_from = r["from_table"].replace(" ", "_")
                safe_to = r["to_table"].replace(" ", "_")
                mermaid_lines.append(f"    {safe_from} -->|{r['column']}| {safe_to}")
                seen.add(key)

    return json.dumps({
        "relationships": relationships,
        "count": len(relationships),
        "mermaid": "\n".join(mermaid_lines) if len(mermaid_lines) > 1 else None,
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def compare_records(
    table_name: str,
    record_id_1: int,
    record_id_2: int,
    columns: str = None,
) -> str:
    """
    Compare two records and show differences.
    Useful for auditing, investigating divergences, or debugging.

    Args:
        table_name: Table name
        record_id_1: First record ID
        record_id_2: Second record ID
        columns: Columns to compare, comma-separated (optional, compares all)
    """
    table_check = check_table_name(table_name)
    resolved_table = table_check["corrected"]
    encoded = _sanitize_table_name(resolved_table)

    params1 = {"id": record_id_1}
    params2 = {"id": record_id_2}
    if columns:
        col_list = [c.strip() for c in columns.split(",")]
        params1["column"] = col_list
        params2["column"] = col_list

    qs1 = urllib.parse.urlencode(params1, doseq=True)
    qs2 = urllib.parse.urlencode(params2, doseq=True)

    r1 = make_request(f"{encoded}/retrieve.json?{qs1}")
    r2 = make_request(f"{encoded}/retrieve.json?{qs2}")

    if "error" in r1:
        return json.dumps({"error": f"Record {record_id_1}: {r1['error']}"})
    if "error" in r2:
        return json.dumps({"error": f"Record {record_id_2}: {r2['error']}"})

    # Handle array response (retrieve returns array with one record)
    rec1 = r1[0] if isinstance(r1, list) and r1 else r1
    rec2 = r2[0] if isinstance(r2, list) and r2 else r2

    # Find differences
    all_keys = set(list(rec1.keys()) + list(rec2.keys()))
    differences = {}
    same = {}
    for key in sorted(all_keys):
        v1 = rec1.get(key)
        v2 = rec2.get(key)
        if v1 != v2:
            differences[key] = {"record_1": v1, "record_2": v2}
        else:
            same[key] = v1

    return json.dumps({
        "table": resolved_table,
        "record_1_id": record_id_1,
        "record_2_id": record_id_2,
        "differences": differences,
        "diff_count": len(differences),
        "same_count": len(same),
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def data_quality_report(table_name: str, sample_size: int = 100) -> str:
    """
    Generate a data quality report for a table.
    Checks for empty fields, potential duplicates, and value distributions.

    Args:
        table_name: Table name
        sample_size: Number of records to analyze (default: 100)
    """
    table_check = check_table_name(table_name)
    resolved_table = table_check["corrected"]
    encoded = _sanitize_table_name(resolved_table)

    # Get schema
    schema = _get_schema(resolved_table)
    if not schema:
        return json.dumps({"error": f"Could not get schema for '{resolved_table}'"})

    columns = schema.get("columns", [])
    col_names = [c["name"] for c in columns if not c.get("isSystem")]

    # Get sample records
    params = {"top": min(sample_size, 500)}
    qs = urllib.parse.urlencode(params)
    result = make_request(f"{encoded}/select.json?{qs}")

    if "error" in result:
        return json.dumps({"error": result["error"]})

    records = result if isinstance(result, list) else result.get("records", result)
    total = len(records) if isinstance(records, list) else 0

    if total == 0:
        return json.dumps({"table": resolved_table, "total_records": 0, "message": "Table is empty"})

    # Analyze each column
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

        # Check for potential duplicates in text columns
        if non_null and isinstance(non_null[0], str):
            unique = len(set(non_null))
            if unique < len(non_null):
                stat["duplicate_values"] = len(non_null) - unique

        col_stats[col] = stat

    # Find columns with highest empty rate
    empty_cols = sorted(
        [(k, v["empty_pct"]) for k, v in col_stats.items() if v["empty_pct"] > 0],
        key=lambda x: x[1], reverse=True,
    )

    return json.dumps({
        "table": resolved_table,
        "records_analyzed": total,
        "total_columns": len(col_names),
        "columns_with_empties": len(empty_cols),
        "worst_empty_columns": empty_cols[:10],
        "column_details": col_stats,
    }, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
