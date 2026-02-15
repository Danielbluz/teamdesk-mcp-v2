"""
Security tests for TeamDesk MCP Server.
Tests input sanitization, filter injection prevention, and API key validation.
"""

import os
os.environ["TEAMDESK_TOKEN"] = "TEST_TOKEN_123"
os.environ["TEAMDESK_DATABASE_ID"] = "99999"

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import urllib.parse
from unittest.mock import patch

import pytest

from server import sanitize_search_text


# ============================================================================
# Filter injection via search_records
# ============================================================================

class TestFilterInjection:
    def test_single_quote_escaped(self):
        """Single quotes in search text must be doubled to prevent injection."""
        result = sanitize_search_text("test' Or 1=1 Or '")
        assert result == "test'' Or 1=1 Or ''"

    def test_normal_text_unchanged(self):
        result = sanitize_search_text("Solar Panel")
        assert result == "Solar Panel"

    def test_empty_string(self):
        result = sanitize_search_text("")
        assert result == ""

    def test_double_quotes_preserved(self):
        """Double quotes should not be escaped (TeamDesk uses single quotes)."""
        result = sanitize_search_text('value "with" quotes')
        assert result == 'value "with" quotes'

    def test_accented_chars_preserved(self):
        result = sanitize_search_text("Geração Irradiação")
        assert result == "Geração Irradiação"

    @patch("server.urllib.request.urlopen")
    def test_injection_in_search_records(self, mock_urlopen):
        """Verify search_records properly sanitizes injected text."""
        from server import search_records

        class FakeResp:
            def read(self): return b"[]"
            def __enter__(self): return self
            def __exit__(self, *a): pass
            headers = {"Content-Type": "application/json"}

        mock_urlopen.return_value = FakeResp()
        search_records("Cliente", "test' Or 1=1 Or '")
        url = mock_urlopen.call_args[0][0].full_url
        # URL-decode to check the filter content
        decoded = urllib.parse.unquote_plus(url)
        # The injected quote should be doubled (escaped)
        assert "test'' Or 1=1 Or ''" in decoded


# ============================================================================
# API Key format validation (SSE server)
# ============================================================================

class TestApiKeyValidation:
    """Test the API key format validation used by the SSE server."""

    @staticmethod
    def _get_validator():
        deploy_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy")
        if deploy_path not in sys.path:
            sys.path.insert(0, deploy_path)
        # Force reimport in case cached
        if "server_sse" in sys.modules:
            del sys.modules["server_sse"]
        from server_sse import validate_api_key_format
        return validate_api_key_format

    def test_valid_key(self):
        fn = self._get_validator()
        assert fn("abc123_valid-key.test") is True

    def test_too_short(self):
        fn = self._get_validator()
        assert fn("abc") is False

    def test_special_chars_rejected(self):
        fn = self._get_validator()
        assert fn("key' OR '1'='1") is False
        assert fn("key; DROP TABLE") is False
        assert fn("key\ninjection") is False

    def test_max_length(self):
        fn = self._get_validator()
        long_key = "a" * 128
        assert fn(long_key) is True
        too_long = "a" * 129
        assert fn(too_long) is False


# ============================================================================
# Table name URL encoding (not stripping)
# ============================================================================

class TestTableNameSafety:
    """Verify table names are URL-encoded, not character-stripped."""

    @patch("server.urllib.request.urlopen")
    def test_accents_preserved(self, mock_urlopen):
        from server import describe_table

        class FakeResp:
            def read(self): return b'{"columns":[]}'
            def __enter__(self): return self
            def __exit__(self, *a): pass
            headers = {"Content-Type": "application/json"}

        mock_urlopen.return_value = FakeResp()
        describe_table("Irradiação Global")
        url = mock_urlopen.call_args[0][0].full_url
        # Must be URL-encoded, not stripped
        assert urllib.parse.quote("Irradiação Global") in url

    @patch("server.urllib.request.urlopen")
    def test_parentheses_encoded(self, mock_urlopen):
        from server import describe_table

        class FakeResp:
            def read(self): return b'{"columns":[]}'
            def __enter__(self): return self
            def __exit__(self, *a): pass
            headers = {"Content-Type": "application/json"}

        mock_urlopen.return_value = FakeResp()
        describe_table("PR Mês (%)")
        url = mock_urlopen.call_args[0][0].full_url
        # Parentheses and % should be encoded
        assert urllib.parse.quote("PR Mês (%)") in url
