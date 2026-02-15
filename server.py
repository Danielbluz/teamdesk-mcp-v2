"""
TeamDesk MCP Server - FastMCP stdio
Connects any MCP-compatible client (Claude Desktop, Claude Code, etc.)
to the TeamDesk REST API v2.

Usage:
    python server.py
"""

import json
import os
import urllib.request
import urllib.parse
import urllib.error
from typing import Any

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load .env if present
load_dotenv()

# Configuration from environment
TEAMDESK_TOKEN = os.getenv("TEAMDESK_TOKEN", "")
TEAMDESK_DATABASE_ID = os.getenv("TEAMDESK_DATABASE_ID", "")
TEAMDESK_BASE_URL = "https://www.teamdesk.net/secure/api/v2"

if not TEAMDESK_TOKEN or not TEAMDESK_DATABASE_ID:
    import sys
    print(
        "WARNING: TEAMDESK_TOKEN and TEAMDESK_DATABASE_ID must be set.\n"
        "Copy .env.example to .env and fill in your credentials.",
        file=sys.stderr,
    )

# Initialize MCP server
mcp = FastMCP("TeamDesk MCP")


def _sanitize_table_name(name: str) -> str:
    """URL-encode table name to handle accented characters safely."""
    return urllib.parse.quote(name, safe="")


def sanitize_search_text(text: str) -> str:
    """Escape single quotes in search text to prevent filter injection."""
    return text.replace("'", "''")


def make_request(endpoint: str, method: str = "GET", data: Any = None) -> dict:
    """Make a request to the TeamDesk API."""
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

    request = urllib.request.Request(
        url, data=req_data, headers=headers, method=method
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else str(e)
        return {"error": f"HTTP {e.code}: {error_body}"}
    except Exception as e:
        return {"error": str(e)}


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
def create_record(table_name: str, data: str) -> str:
    """
    Create a new record in a table.

    Args:
        table_name: Table name
        data: Record data as JSON string (e.g. '{"Nome": "Test", "Status": "Ativo"}')
    """
    encoded = _sanitize_table_name(table_name)

    try:
        record_data = json.loads(data)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON - {e}"

    result = make_request(f"{encoded}/create.json", method="POST", data=[record_data])

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def update_record(table_name: str, record_id: int, data: str) -> str:
    """
    Update an existing record.

    Args:
        table_name: Table name
        record_id: Record ID to update
        data: Data to update as JSON string (e.g. '{"Status": "Inativo"}')
    """
    encoded = _sanitize_table_name(table_name)

    try:
        record_data = json.loads(data)
        record_data["@row.id"] = record_id
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON - {e}"

    result = make_request(f"{encoded}/update.json", method="POST", data=[record_data])

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
    table_name: str, search_text: str, columns: str = None, top: int = 50
) -> str:
    """
    Search records containing the specified text.

    Args:
        table_name: Table name
        search_text: Text to search for
        columns: Columns to return, comma-separated (optional)
        top: Maximum results (default: 50)
    """
    encoded = _sanitize_table_name(table_name)
    safe_text = sanitize_search_text(search_text)

    filter_expr = f"Contains([*], '{safe_text}')"

    params = {"top": min(top, 500), "filter": filter_expr}
    if columns:
        params["column"] = columns.split(",")

    query_string = urllib.parse.urlencode(params, doseq=True)
    result = make_request(f"{encoded}/select.json?{query_string}")

    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2, ensure_ascii=False)


@mcp.tool()
def upsert_records(table_name: str, match_column: str, data: str) -> str:
    """
    Insert or update records (upsert) in a table.
    If a record with the match_column value exists, it updates. Otherwise, it creates.

    Args:
        table_name: Table name
        match_column: Column used for matching (must be marked as Unique in TeamDesk)
        data: JSON array of records (e.g. '[{"Nome": "X", "Valor": 1}]')
    """
    encoded = _sanitize_table_name(table_name)
    encoded_match = urllib.parse.quote(match_column, safe="")

    try:
        records = json.loads(data)
        if not isinstance(records, list):
            records = [records]
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON - {e}"

    result = make_request(
        f"{encoded}/upsert.json?match={encoded_match}",
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


if __name__ == "__main__":
    mcp.run()
