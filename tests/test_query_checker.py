"""
Tests for td_query_checker — validates all gotcha corrections.
Run: python -m pytest tests/test_query_checker.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from td_query_checker import (
    check_filter,
    check_columns,
    check_table_name,
    check_upsert,
    check_all,
    broaden_filter,
)


# ---------------------------------------------------------------------------
# Sample schema (simulates describe_table output)
# ---------------------------------------------------------------------------
SCHEMA_GERACAO_DIA = {
    "columns": [
        {"name": "Instalação"},
        {"name": "Data"},
        {"name": "Geração dia (kWh)"},
        {"name": "Geração Huawei"},
        {"name": "Geração Sungrow"},
        {"name": "Geração Afore"},
        {"name": "Ajuste Manual"},
        {"name": "Origem"},
        {"name": "Unidade Geradora"},
    ]
}

SCHEMA_USINA = {
    "columns": [
        {"name": "Nome"},
        {"name": "Instalação"},
        {"name": "Potência (kW)"},
        {"name": "Potência Pico (kWp)"},
        {"name": "Status"},
        {"name": "Distribuidora"},
        {"name": "Grupo"},
        {"name": "Município UF"},
        {"name": "Porte"},
    ]
}


# ===========================================================================
# Filter checks
# ===========================================================================

class TestFilterAccents:
    """Gotcha #1: Acentos exatos nas colunas."""

    def test_fix_geracao_accent(self):
        r = check_filter("[Geracao] >= 100")
        assert "[Geração]" in r["corrected"]
        assert r["auto_fixed"]

    def test_fix_instalacao_accent(self):
        r = check_filter("[Instalacao] = '3014576923'")
        assert "[Instalação]" in r["corrected"]

    def test_fix_irradiacao_accent(self):
        r = check_filter("[Irradiacao] > 5")
        assert "[Irradiação]" in r["corrected"]

    def test_fix_potencia_accent(self):
        r = check_filter("[Potencia (kW)] >= 1000")
        assert "[Potência (kW)]" in r["corrected"]

    def test_fix_mes_accent(self):
        r = check_filter("[Mes de Referencia] >= #2026-01-01#")
        assert "[Mês de Referência]" in r["corrected"]

    def test_no_fix_correct_accent(self):
        r = check_filter("[Geração] >= 100")
        assert not r["auto_fixed"]
        assert r["corrected"] == "[Geração] >= 100"

    def test_fix_municipio_accent(self):
        r = check_filter("[Municipio UF] = 'Paracatu-MG'")
        assert "[Município UF]" in r["corrected"]

    def test_schema_fuzzy_match(self):
        """Column not in ACCENT_FIXES but matches schema via fuzzy."""
        r = check_filter("[Unidade geradora] = 'Paracatu'", SCHEMA_GERACAO_DIA)
        assert "[Unidade Geradora]" in r["corrected"]


class TestFilterLike:
    """Gotcha #3: LIKE não é suportado."""

    def test_detect_like(self):
        r = check_filter("[Nome] LIKE '%Paracatu%'")
        assert any(i["type"] == "forbidden_operator" for i in r["issues"])

    def test_auto_fix_like_to_contains(self):
        r = check_filter("[Nome] LIKE '%Paracatu%'")
        assert "Contains([Nome], 'Paracatu')" in r["corrected"]

    def test_auto_fix_like_prefix_only(self):
        """LIKE 'Paracatu%' (no leading %) should also be converted."""
        r = check_filter("[Nome] LIKE 'Paracatu%'")
        assert "Contains([Nome], 'Paracatu')" in r["corrected"]

    def test_auto_fix_like_suffix_only(self):
        """LIKE '%Paracatu' (no trailing %) should also be converted."""
        r = check_filter("[Nome] LIKE '%Paracatu'")
        assert "Contains([Nome], 'Paracatu')" in r["corrected"]

    def test_auto_fix_like_no_wildcards(self):
        """LIKE 'Paracatu' (no %) should also be converted."""
        r = check_filter("[Nome] LIKE 'Paracatu'")
        assert "Contains([Nome], 'Paracatu')" in r["corrected"]

    def test_detect_not_like(self):
        r = check_filter("[Nome] NOT LIKE '%Test%'")
        assert any("NOT LIKE" in i["message"] for i in r["issues"])


class TestFilterDates:
    """Gotcha: Formato de data deve ser #YYYY-MM-DD#."""

    def test_fix_single_quote_date(self):
        r = check_filter("[Data] >= '2026-01-01'")
        assert "#2026-01-01#" in r["corrected"]

    def test_fix_double_quote_date(self):
        r = check_filter('[Data] >= "2026-01-01"')
        assert "#2026-01-01#" in r["corrected"]

    def test_fix_brazilian_date_format(self):
        r = check_filter("[Data] >= #01/03/2026#")
        assert "#2026-03-01#" in r["corrected"]

    def test_no_fix_correct_date(self):
        r = check_filter("[Data] >= #2026-01-01#")
        assert not r["auto_fixed"]

    def test_fix_multiple_dates(self):
        r = check_filter("[Data] >= '2026-01-01' and [Data] <= '2026-01-31'")
        assert "#2026-01-01#" in r["corrected"]
        assert "#2026-01-31#" in r["corrected"]


class TestFilterLogicOps:
    """Gotcha: Operadores lógicos devem ser minúsculos."""

    def test_fix_uppercase_and(self):
        r = check_filter("[A] = 1 AND [B] = 2")
        assert " and " in r["corrected"]
        assert " AND " not in r["corrected"]

    def test_fix_uppercase_or(self):
        r = check_filter("[A] = 1 OR [B] = 2")
        assert " or " in r["corrected"]

    def test_fix_titlecase_and(self):
        r = check_filter("[A] = 1 And [B] = 2")
        assert " and " in r["corrected"]

    def test_no_fix_lowercase(self):
        r = check_filter("[A] = 1 and [B] = 2")
        assert not r["auto_fixed"]


class TestFilterForbiddenOps:
    """Gotcha: IS NULL não suportado. In()/Between() ARE valid TeamDesk functions."""

    def test_in_is_valid(self):
        """In() is a valid TeamDesk Formula Language function — must NOT be blocked."""
        r = check_filter("In([Status], 'Ativo', 'Conectada')")
        assert not any(i["type"] == "forbidden_operator" for i in r["issues"])

    def test_between_is_valid(self):
        """Between() is a valid TeamDesk Formula Language function — must NOT be blocked."""
        r = check_filter("Between([Valor], 100, 200)")
        assert not any(i["type"] == "forbidden_operator" for i in r["issues"])

    def test_detect_is_null(self):
        r = check_filter("[Nome] IS NULL")
        assert any("IS NULL" in i["message"] for i in r["issues"])


class TestFilterOperators:
    """!= must be converted to <> (TeamDesk inequality operator)."""

    def test_fix_not_equal(self):
        r = check_filter("[Status] != 'Inativo'")
        assert "<>" in r["corrected"]
        assert "!=" not in r["corrected"]
        assert r["auto_fixed"]

    def test_no_fix_correct_not_equal(self):
        r = check_filter("[Status] <> 'Inativo'")
        assert not r["auto_fixed"]


class TestFilterSchemaValidation:
    """Validação de colunas contra schema real."""

    def test_valid_column_with_schema(self):
        r = check_filter("[Status] = 'Conectada'", SCHEMA_USINA)
        assert r["valid"]

    def test_invalid_column_with_suggestion(self):
        r = check_filter("[nome] = 'Paracatu'", SCHEMA_USINA)
        assert "[Nome]" in r["corrected"]

    def test_wildcard_ignored(self):
        r = check_filter("Contains([*], 'test')", SCHEMA_USINA)
        assert r["valid"]


class TestFilterCombined:
    """Cenários reais com múltiplos problemas."""

    def test_real_scenario_all_wrong(self):
        """Simula query com todos os erros comuns."""
        r = check_filter(
            "[Instalacao] = '3014576923' AND [Geracao] >= 100 AND [Data] >= '2026-01-01'"
        )
        assert "[Instalação]" in r["corrected"]
        assert "[Geração]" in r["corrected"]
        assert "#2026-01-01#" in r["corrected"]
        assert " and " in r["corrected"]
        assert r["auto_fixed"]

    def test_real_scenario_correct(self):
        """Query correta não deve ser alterada."""
        original = "Contains([Unidade Geradora], 'Paracatu') and [Data] >= #2026-02-01# and [Data] <= #2026-02-28#"
        r = check_filter(original, SCHEMA_GERACAO_DIA)
        assert not r["auto_fixed"]
        assert r["valid"]

    def test_odd_quotes_detected(self):
        r = check_filter("[Nome] = 'Paracatu")
        assert any(i["type"] == "syntax" for i in r["issues"])


# ===========================================================================
# Column checks
# ===========================================================================

class TestColumns:
    def test_fix_accent_columns(self):
        r = check_columns(["Instalacao", "Geracao dia (kWh)", "Status"])
        assert r["corrected"][0] == "Instalação"
        assert r["corrected"][1] == "Geração dia (kWh)"
        assert r["corrected"][2] == "Status"

    def test_schema_fuzzy_match_with_accent(self):
        """With schema, 'potencia' fuzzy-matches 'Potência (kW)' from schema."""
        r = check_columns(["Nome", "potencia"], SCHEMA_USINA)
        assert any(i["type"] == "column_not_found" for i in r["issues"])
        assert r["corrected"][1] == "Potência (kW)"  # Full name from schema

    def test_schema_fuzzy_unknown_column(self):
        """Column not in ACCENT_FIXES, matched via fuzzy against schema."""
        r = check_columns(["distribuidora"], SCHEMA_USINA)
        assert r["corrected"][0] == "Distribuidora"

    def test_schema_overrides_accent_fixes(self):
        """Schema must override ACCENT_FIXES when column name is correct without accent."""
        # Geracao_Dia has "Geracao dia (kWh)" WITHOUT accent
        schema_gd = {"columns": [
            {"name": "Geracao dia (kWh)"},
            {"name": "Geração Huawei (kWh)"},
            {"name": "Data"},
        ]}
        r = check_columns(["Geracao dia (kWh)"], schema_gd)
        assert r["corrected"][0] == "Geracao dia (kWh)"  # Must NOT add accent
        assert r["valid"]

    def test_all_correct(self):
        r = check_columns(["Nome", "Status", "Distribuidora"], SCHEMA_USINA)
        assert r["valid"]
        assert len(r["issues"]) == 0


# ===========================================================================
# Table name checks
# ===========================================================================

class TestTableName:
    def test_fix_cusd_shorthand(self):
        r = check_table_name("CUSD")
        assert r["corrected"] == "Fatura Uso (CUSD)"

    def test_fix_geracao_mensal(self):
        r = check_table_name("Geracao Mensal")
        assert r["corrected"] == "Geração Mensal"

    def test_fix_alarmes_variants(self):
        r = check_table_name("Alarmes Fusion")
        assert r["corrected"] == "Alarme Fusion"

    def test_fix_sungrow_variant(self):
        r = check_table_name("Alarme Sungrow")
        assert r["corrected"] == "Alarmes_Sungrow"

    def test_no_fix_correct_name(self):
        r = check_table_name("Usina Solar")
        assert r["corrected"] == "Usina Solar"
        assert len(r["issues"]) == 0


# ===========================================================================
# Upsert checks
# ===========================================================================

class TestUpsert:
    def test_detect_dict_not_array(self):
        """Gotcha #2: body deve ser array."""
        r = check_upsert({"Nome": "Test"})
        assert any(i["type"] == "upsert_format" for i in r["issues"])
        assert isinstance(r["corrected"], list)

    def test_fix_accent_keys(self):
        r = check_upsert([{"Instalacao": "123", "Geracao": 100}])
        assert "Instalação" in r["corrected"][0]
        assert "Geração" in r["corrected"][0]

    def test_scientific_notation_warning(self):
        """Gotcha #23: Notação científica em floats pequenos."""
        r = check_upsert([{"Valor": 0.00004}])
        assert any(i["type"] == "scientific_notation" for i in r["issues"])

    def test_normal_float_no_warning(self):
        r = check_upsert([{"Valor": 123.45}])
        assert not any(i["type"] == "scientific_notation" for i in r["issues"])

    def test_schema_column_correction(self):
        r = check_upsert(
            [{"instalação": "123", "data": "2026-01-01"}],
            SCHEMA_GERACAO_DIA,
        )
        keys = list(r["corrected"][0].keys())
        assert "Instalação" in keys or "Data" in keys


# ===========================================================================
# Combined check_all
# ===========================================================================

class TestCheckAll:
    def test_full_scenario(self):
        r = check_all(
            table_name="Geracao Mensal",
            filter_expr="[Instalacao] = '123' AND [Geracao] > 0",
            columns=["Instalacao", "Geracao P90 (kWh)", "Mes/Ano"],
        )
        assert r["table"]["corrected"] == "Geração Mensal"
        assert "[Instalação]" in r["filter"]["corrected"]
        assert r["columns"]["corrected"][0] == "Instalação"
        assert r["total_issues"] > 0
        assert r["total_auto_fixed"] > 0

    def test_all_valid(self):
        r = check_all(
            table_name="Usina Solar",
            filter_expr="[Status] = 'Conectada'",
            columns=["Nome", "Status"],
            schema=SCHEMA_USINA,
        )
        assert r["all_valid"]


# ===========================================================================
# Broaden filter (self-correction loop)
# ===========================================================================

class TestBroadenFilter:
    def test_exact_to_contains(self):
        suggestions = broaden_filter("[Nome] = 'Paracatu'")
        contains_strat = [s for s in suggestions if s["strategy"] == "exact_to_contains"]
        assert len(contains_strat) == 1
        assert "Contains([Nome], 'Paracatu')" in contains_strat[0]["filter"]

    def test_no_exact_to_contains_when_already_contains(self):
        """Should not suggest exact_to_contains if filter already uses Contains."""
        suggestions = broaden_filter("Contains([Nome], 'Paracatu')")
        assert not any(s["strategy"] == "exact_to_contains" for s in suggestions)

    def test_widen_dates(self):
        suggestions = broaden_filter(
            "[Data] >= #2026-01-01# and [Data] <= #2026-01-31#"
        )
        widen = [s for s in suggestions if s["strategy"] == "widen_dates"]
        assert len(widen) == 1
        # Start date should be 30 days earlier (2025-12-02)
        assert "#2025-12-02#" in widen[0]["filter"]
        # End date should be 30 days later (2026-03-02)
        assert "#2026-03-02#" in widen[0]["filter"]

    def test_remove_last_clause(self):
        suggestions = broaden_filter(
            "Contains([Nome], 'Paracatu') and [Status] = 'Conectada' and [Data] >= #2026-01-01#"
        )
        remove = [s for s in suggestions if s["strategy"] == "remove_last_clause"]
        assert len(remove) == 1
        assert "[Data]" not in remove[0]["filter"]
        assert "Paracatu" in remove[0]["filter"]
        assert "Conectada" in remove[0]["filter"]

    def test_no_remove_clause_single_condition(self):
        """Single condition should not have remove_last_clause strategy."""
        suggestions = broaden_filter("[Nome] = 'Test'")
        assert not any(s["strategy"] == "remove_last_clause" for s in suggestions)

    def test_always_has_no_filter_diagnostic(self):
        suggestions = broaden_filter("[Status] = 'Conectada'")
        no_filter = [s for s in suggestions if s["strategy"] == "no_filter"]
        assert len(no_filter) == 1
        assert no_filter[0]["filter"] is None
        assert no_filter[0]["is_diagnostic"]

    def test_multiple_exact_matches(self):
        """Multiple exact matches should all be converted to Contains."""
        suggestions = broaden_filter("[Nome] = 'Paracatu' and [Status] = 'Ativo'")
        contains = [s for s in suggestions if s["strategy"] == "exact_to_contains"]
        assert len(contains) == 1
        assert "Contains([Nome], 'Paracatu')" in contains[0]["filter"]
        assert "Contains([Status], 'Ativo')" in contains[0]["filter"]

    def test_order_of_strategies(self):
        """Strategies should be in order: contains, dates, remove, no_filter."""
        suggestions = broaden_filter(
            "[Nome] = 'Paracatu' and [Data] >= #2026-01-01# and [Data] <= #2026-01-31#"
        )
        strategies = [s["strategy"] for s in suggestions]
        assert strategies.index("exact_to_contains") < strategies.index("no_filter")
        assert strategies.index("widen_dates") < strategies.index("no_filter")
        assert strategies[-1] == "no_filter"
