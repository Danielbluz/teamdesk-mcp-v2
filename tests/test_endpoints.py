"""
Tests for TeamDesk MCP Server endpoint URL construction and HTTP methods.
Uses mocking — no real API calls are made.
"""

import json
import urllib.parse
from unittest.mock import patch, MagicMock

import pytest

# We need to set env vars before importing server
import os
os.environ["TEAMDESK_TOKEN"] = "TEST_TOKEN_123"
os.environ["TEAMDESK_DATABASE_ID"] = "99999"

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import (
    make_request,
    list_tables,
    describe_table,
    get_records,
    select_view,
    get_record,
    create_record,
    update_record,
    delete_record,
    search_records,
    upsert_records,
    gerar_documento,
    sanitize_search_text,
    TEAMDESK_BASE_URL,
    TEAMDESK_DATABASE_ID,
)


BASE = f"{TEAMDESK_BASE_URL}/{TEAMDESK_DATABASE_ID}"


class FakeResponse:
    """Fake urllib response for testing."""
    def __init__(self, data, status=200, content_type="application/json"):
        self._data = json.dumps(data).encode("utf-8") if isinstance(data, (dict, list)) else data
        self.status = status
        self.headers = {"Content-Type": content_type}

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def capture_request(fake_data):
    """Decorator to capture the URL and method of make_request calls."""
    captured = {}

    def mock_urlopen(request):
        captured["url"] = request.full_url
        captured["method"] = request.method
        captured["data"] = request.data
        captured["headers"] = dict(request.headers)
        return FakeResponse(fake_data)

    return captured, mock_urlopen


# ============================================================================
# list_tables
# ============================================================================

class TestListTables:
    @patch("server.urllib.request.urlopen")
    def test_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"tables": [{"id": 1, "recordName": "Test", "recordsName": "Tests"}]})
        result = list_tables()
        url = mock_urlopen.call_args[0][0].full_url
        assert url == f"{BASE}/describe.json"
        assert mock_urlopen.call_args[0][0].method == "GET"

    @patch("server.urllib.request.urlopen")
    def test_returns_table_list(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"tables": [
            {"id": 1, "recordName": "Usina Solar", "recordsName": "Usinas Solares"},
            {"id": 2, "recordName": "Cliente", "recordsName": "Clientes"},
        ]})
        result = json.loads(list_tables())
        assert len(result) == 2
        assert result[0]["name"] == "Usina Solar"


# ============================================================================
# describe_table
# ============================================================================

class TestDescribeTable:
    @patch("server.urllib.request.urlopen")
    def test_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"columns": []})
        describe_table("Usina Solar")
        url = mock_urlopen.call_args[0][0].full_url
        assert "/Usina%20Solar/describe.json" in url

    @patch("server.urllib.request.urlopen")
    def test_accented_name(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"columns": []})
        describe_table("Geração Mensal")
        url = mock_urlopen.call_args[0][0].full_url
        assert urllib.parse.quote("Geração Mensal") in url


# ============================================================================
# select_data
# ============================================================================

class TestGetRecords:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_basic(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("Cliente")
        url = mock_urlopen.call_args[0][0].full_url
        assert "/Cliente/select.json?" in url
        assert "top=100" in url

    @patch("server.urllib.request.urlopen")
    def test_with_filter(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("Cliente", filter_expr="[Status] = 'Ativo'")
        url = mock_urlopen.call_args[0][0].full_url
        assert "filter=" in url

    @patch("server.urllib.request.urlopen")
    def test_sort_desc(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("Cliente", sort="Nome//DESC")
        url = mock_urlopen.call_args[0][0].full_url
        assert "sort=" in url

    @patch("server.urllib.request.urlopen")
    def test_max_top_capped(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("Cliente", top=9999)
        url = mock_urlopen.call_args[0][0].full_url
        assert "top=500" in url


# ============================================================================
# select_view
# ============================================================================

class TestSelectView:
    @patch("server.urllib.request.urlopen")
    def test_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        select_view("Cliente", "Ativos")
        url = mock_urlopen.call_args[0][0].full_url
        # Correct format: {table}/{view}/select.json
        assert "/Cliente/Ativos/select.json" in url


# ============================================================================
# get_record
# ============================================================================

class TestGetRecord:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_uses_retrieve(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"@row.id": 42})
        get_record("Cliente", 42)
        url = mock_urlopen.call_args[0][0].full_url
        # Must use retrieve.json?id=X, NOT {id}.json
        assert "/Cliente/retrieve.json?id=42" in url
        assert mock_urlopen.call_args[0][0].method == "GET"

    @patch("server.urllib.request.urlopen")
    def test_does_not_use_old_format(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"@row.id": 42})
        get_record("Cliente", 42)
        url = mock_urlopen.call_args[0][0].full_url
        # Old incorrect format should NOT be used
        assert "/Cliente/42.json" not in url


# ============================================================================
# create_record
# ============================================================================

class TestCreateRecord:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_and_method(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([{"@row.id": 1}])
        create_record("Cliente", '{"Nome": "Test"}')
        req = mock_urlopen.call_args[0][0]
        assert "/Cliente/create.json" in req.full_url
        assert req.method == "POST"

    @patch("server.urllib.request.urlopen")
    def test_body_is_array(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([{"@row.id": 1}])
        create_record("Cliente", '{"Nome": "Test"}')
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert isinstance(body, list), "Body must be an array"


# ============================================================================
# update_record
# ============================================================================

class TestUpdateRecord:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_and_method(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([{"@row.id": 42}])
        update_record("Cliente", 42, '{"Status": "Inativo"}')
        req = mock_urlopen.call_args[0][0]
        assert "/Cliente/update.json" in req.full_url
        assert req.method == "POST"

    @patch("server.urllib.request.urlopen")
    def test_body_includes_row_id(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([{"@row.id": 42}])
        update_record("Cliente", 42, '{"Status": "Inativo"}')
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert isinstance(body, list)
        assert body[0]["@row.id"] == 42


# ============================================================================
# delete_record
# ============================================================================

class TestDeleteRecord:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_uses_get(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({"deleted": True})
        delete_record("Cliente", 42)
        req = mock_urlopen.call_args[0][0]
        assert "/Cliente/delete.json?id=42" in req.full_url
        # TeamDesk uses GET for delete
        assert req.method == "GET"


# ============================================================================
# search_records
# ============================================================================

class TestSearchRecords:
    @patch("server.urllib.request.urlopen")
    def test_endpoint(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        search_records("Cliente", "Solar")
        url = mock_urlopen.call_args[0][0].full_url
        assert "/Cliente/select.json?" in url
        assert "Contains" in urllib.parse.unquote(url)

    @patch("server.urllib.request.urlopen")
    def test_uses_wildcard_column(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        search_records("Cliente", "test")
        url = urllib.parse.unquote(mock_urlopen.call_args[0][0].full_url)
        assert "[*]" in url


# ============================================================================
# upsert_records
# ============================================================================

class TestUpsertRecords:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_and_method(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([{"@row.id": 1}])
        upsert_records("Cliente", "Chave_Unica", '[{"Chave_Unica": "X", "Nome": "Test"}]')
        req = mock_urlopen.call_args[0][0]
        assert "/Cliente/upsert.json?match=" in req.full_url
        assert req.method == "POST"

    @patch("server.urllib.request.urlopen")
    def test_body_is_array(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([{"@row.id": 1}])
        upsert_records("Cliente", "Chave", '{"Chave": "X"}')
        body = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        assert isinstance(body, list), "Body must be an array even for single record"


# ============================================================================
# gerar_documento
# ============================================================================

class TestGerarDocumento:
    @patch("server.urllib.request.urlopen")
    def test_endpoint_no_json_suffix(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse(
            b"PK\x03\x04...", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        # Mock open to avoid writing files
        from unittest.mock import mock_open
        with patch("builtins.open", mock_open()):
            with patch("os.makedirs"):
                gerar_documento("Relatorio", "Template1", 42)

        url = mock_urlopen.call_args[0][0].full_url
        # Must use /document?id=X (NOT /document.json?id=X)
        assert "/document?id=42" in url
        assert "/document.json" not in url


# ============================================================================
# URL encoding with accents and special chars
# ============================================================================

class TestUrlEncoding:
    @patch("server.urllib.request.urlopen")
    def test_table_with_accents(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("Geração Mensal")
        url = mock_urlopen.call_args[0][0].full_url
        encoded = urllib.parse.quote("Geração Mensal")
        assert encoded in url

    @patch("server.urllib.request.urlopen")
    def test_table_with_parentheses(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("T_Amb (ºC)")
        url = mock_urlopen.call_args[0][0].full_url
        # Parentheses should be URL-encoded, not stripped
        encoded = urllib.parse.quote("T_Amb (ºC)")
        assert encoded in url

    @patch("server.urllib.request.urlopen")
    def test_sort_double_slash_desc(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse([])
        get_records("Cliente", sort="Data//DESC")
        url = mock_urlopen.call_args[0][0].full_url
        # Sort syntax uses // for direction separator
        assert "sort=" in url
