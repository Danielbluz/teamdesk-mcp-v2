"""
TeamDesk Query Checker — Validates and auto-corrects TeamDesk API filters.

Applies 30+ known gotchas to prevent silent failures in TeamDesk queries.
Designed to be used standalone or integrated into the MCP TeamDesk server.

Usage:
    from td_query_checker import check_filter, check_upsert, check_columns

    # Validate a filter expression
    result = check_filter("[Geracao] >= 100 LIKE '%Paracatu%'", schema)
    print(result["corrected"])  # Fixed filter
    print(result["issues"])     # List of problems found

    # Validate column names
    result = check_columns(["Geracao dia (kWh)", "Instalacao", "Status"], schema)

    # Validate upsert payload
    result = check_upsert({"Nome": "Test"}, schema)
"""

import re
import unicodedata
from typing import Optional


# ---------------------------------------------------------------------------
# Known column accent corrections (most common mistakes)
# Maps wrong → correct spelling
# ---------------------------------------------------------------------------
ACCENT_FIXES = {
    # Geração / Geracao
    "Geracao": "Geração",
    "geracao": "Geração",
    "Geracao Mensal": "Geração Mensal",
    "Geracao Inversor": "Geração Inversor",
    "Geracao Huawei": "Geração Huawei",
    "Geracao Sungrow": "Geração Sungrow",
    "Geracao Afore": "Geração Afore",
    "Geracao dia (kWh)": "Geração dia (kWh)",
    "Geracao Prevista (kWh)": "Geração Prevista (kWh)",
    "Geracao P90 (kWh)": "Geração P90 (kWh)",
    "Geracao Realizada O&M (kWh)": "Geração Realizada O&M (kWh)",
    "Geracao Prevista/P90 (%)": "Geração Prevista/P90 (%)",
    # Instalação / Instalacao
    "Instalacao": "Instalação",
    "instalacao": "Instalação",
    "Instalacao Cliente": "Instalação Cliente",
    # Irradiação / Irradiacao
    "Irradiacao": "Irradiação",
    "irradiacao": "Irradiação",
    "Irradiacao Global Horizontal": "Irradiação Global Horizontal",
    # Potência / Potencia
    "Potencia": "Potência",
    "potencia": "Potência",
    "Potencia (kW)": "Potência (kW)",
    "Potencia Pico (kWp)": "Potência Pico (kWp)",
    # Mês / Mes
    "Mes": "Mês",
    "Mes de Referencia": "Mês de Referência",
    "Mes/Ano": "Mês/Ano",
    "Mes (#)": "Mês (#)",
    # Município / Municipio
    "Municipio": "Município",
    "Municipio UF": "Município UF",
    # Referência / Referencia
    "Referencia": "Referência",
    "Mes de Referencia": "Mês de Referência",
    "Referencia Externa": "Referência Externa",
    # Número / Numero
    "Numero": "Número",
    "Numero Fatura": "Número Fatura",
    # Versão / Versao
    "Versao": "Versão",
    "Versao PVSyst": "Versão PVSyst",
    # Ocorrência / Ocorrencia
    "Ocorrencia": "Ocorrência",
    "Hora da Ocorrencia": "Hora da Ocorrência",
    # Descrição / Descricao
    "Descricao": "Descrição",
    # Código / Codigo
    "Codigo": "Código",
    # Título / Titulo
    "Titulo": "Título",
    # Situação / Situacao
    "Situacao": "Situação",
    # Typo histórico: Enegia → Energia
    "Enegia Injetada Líquida (kWh)": "Energia Injetada Líquida (kWh)",
    # Previsão / Previsao
    "Previsao": "Previsão",
    # Índice / Indice
    "Indice": "Índice",
    # Edição / Edicao
    "Edicao": "Edição",
    # Período / Periodo
    "Periodo": "Período",
    # Razão / Razao
    "Razao": "Razão",
    # Padrão / Padrao
    "Padrao": "Padrão",
    # Conexão / Conexao
    "Conexao": "Conexão",
    # Compensação / Compensacao
    "Compensacao": "Compensação",
}

# ---------------------------------------------------------------------------
# Table name corrections (common misspellings)
# ---------------------------------------------------------------------------
TABLE_FIXES = {
    "Geracao Mensal": "Geração Mensal",
    "Geracao_Dia": "Geracao_Dia",  # This one actually has no accent in TD
    "Geracao Inversor": "Geração Inversor",
    "Geracao Sungrow": "Geração Sungrow",
    "Geracao Huawei": "Geração Huawei",
    "Geracao Afore": "Geração Afore",
    "Fatura Uso CUSD": "Fatura Uso (CUSD)",
    "Fatura CUSD": "Fatura Uso (CUSD)",
    "CUSD": "Fatura Uso (CUSD)",
    "Alarme FusionSolar": "Alarme Fusion",
    "Alarmes Fusion": "Alarme Fusion",
    "Alarmes Sungrow": "Alarmes_Sungrow",
    "Alarme Sungrow": "Alarmes_Sungrow",
    "Tarifa": "Tarifa de Energia",
    "Tarifas": "Tarifa de Energia",
    "Relatorio O&M": "Relatório O&M",
    "Relatorio": "Relatório O&M",
    "Termo Cessao": "Termo de Cessão",
    "CS Gerador": "CS GERADOR",
    "CS Consumo": "CS CONSUMO",
    "Geracao PVSyst": "Geração PVSyst",
}

# ---------------------------------------------------------------------------
# Forbidden patterns in filters
# ---------------------------------------------------------------------------
FORBIDDEN_PATTERNS = [
    {
        "pattern": r"\bLIKE\b",
        "message": "LIKE não é suportado no TeamDesk. Use Contains([campo], 'valor')",
        "fix_hint": "LIKE '%X%' → Contains([campo], 'X')",
    },
    {
        "pattern": r"\bIN\s*\(",
        "message": "IN() não é suportado. Use múltiplos OR: [campo]='a' or [campo]='b'",
        "fix_hint": "IN('a','b') → [campo]='a' or [campo]='b'",
    },
    {
        "pattern": r"\bBETWEEN\b",
        "message": "BETWEEN não é suportado. Use >= AND <=",
        "fix_hint": "BETWEEN a AND b → [campo]>=a and [campo]<=b",
    },
    {
        "pattern": r"\bIS\s+NULL\b",
        "message": "IS NULL não é suportado. Use IsNull([campo])",
        "fix_hint": "campo IS NULL → IsNull([campo])",
    },
    {
        "pattern": r"\bIS\s+NOT\s+NULL\b",
        "message": "IS NOT NULL não é suportado. Use not IsNull([campo])",
        "fix_hint": "campo IS NOT NULL → not IsNull([campo])",
    },
    {
        "pattern": r"\bNOT\s+LIKE\b",
        "message": "NOT LIKE não é suportado. Use not Contains([campo], 'valor')",
        "fix_hint": "NOT LIKE '%X%' → not Contains([campo], 'X')",
    },
]

# ---------------------------------------------------------------------------
# Date format validation
# ---------------------------------------------------------------------------
DATE_WRONG_FORMATS = [
    # 'YYYY-MM-DD' (aspas simples em vez de #)
    {
        "pattern": r"'(\d{4}-\d{2}-\d{2})'",
        "message": "Data com aspas simples. TeamDesk exige formato #YYYY-MM-DD#",
        "fix": lambda m: f"#{m.group(1)}#",
    },
    # "YYYY-MM-DD" (aspas duplas em vez de #)
    {
        "pattern": r'"(\d{4}-\d{2}-\d{2})"',
        "message": "Data com aspas duplas. TeamDesk exige formato #YYYY-MM-DD#",
        "fix": lambda m: f"#{m.group(1)}#",
    },
    # DD/MM/YYYY (formato brasileiro)
    {
        "pattern": r"#(\d{2})/(\d{2})/(\d{4})#",
        "message": "Data em formato DD/MM/YYYY. TeamDesk exige #YYYY-MM-DD#",
        "fix": lambda m: f"#{m.group(3)}-{m.group(2)}-{m.group(1)}#",
    },
    # DD/MM/YYYY sem #
    {
        "pattern": r"(?<![#\d])(\d{2})/(\d{2})/(\d{4})(?![#\d])",
        "message": "Data em formato DD/MM/YYYY sem delimitadores #. Use #YYYY-MM-DD#",
        "fix": lambda m: f"#{m.group(3)}-{m.group(2)}-{m.group(1)}#",
    },
]

# ---------------------------------------------------------------------------
# Logical operator corrections
# ---------------------------------------------------------------------------
LOGIC_OP_FIXES = [
    {"pattern": r"\bAND\b", "correct": "and", "message": "AND deve ser minúsculo: and"},
    {"pattern": r"\bOR\b", "correct": "or", "message": "OR deve ser minúsculo: or"},
    {"pattern": r"\bNOT\b(?!\s+NULL)", "correct": "not", "message": "NOT deve ser minúsculo: not"},
    {"pattern": r"\bAnd\b", "correct": "and", "message": "And deve ser minúsculo: and"},
    {"pattern": r"\bOr\b", "correct": "or", "message": "Or deve ser minúsculo: or"},
    {"pattern": r"\bNot\b", "correct": "not", "message": "Not deve ser minúsculo: not"},
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _strip_accents(text: str) -> str:
    """Remove accents from text for fuzzy comparison."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _fuzzy_match_column(name: str, valid_columns: list[str]) -> Optional[str]:
    """Find best matching column name using accent-insensitive comparison."""
    name_stripped = _strip_accents(name).lower()
    for col in valid_columns:
        if _strip_accents(col).lower() == name_stripped:
            return col
    # Partial match
    for col in valid_columns:
        if name_stripped in _strip_accents(col).lower():
            return col
    return None


def _extract_column_refs(filter_str: str) -> list[str]:
    """Extract column names from [Column Name] references in a filter."""
    return re.findall(r"\[([^\]]+)\]", filter_str)


def _extract_function_args(filter_str: str) -> list[str]:
    """Extract column names from function calls like Contains([Col], 'val')."""
    return re.findall(r"(?:Contains|IsNull|Sum|Avg|Count)\(\[([^\]]+)\]", filter_str)


# ---------------------------------------------------------------------------
# Main checker functions
# ---------------------------------------------------------------------------

def check_filter(
    filter_expr: str,
    schema: Optional[dict] = None,
) -> dict:
    """
    Validate and auto-correct a TeamDesk filter expression.

    Args:
        filter_expr: The filter expression to validate.
            Example: "[Geracao] >= 100 AND Contains([Nome], 'Paracatu')"
        schema: Optional table schema from describe_table().
            If provided, validates column names against actual schema.
            Expected format: {"columns": [{"name": "Col Name", ...}, ...]}

    Returns:
        dict with keys:
            - valid (bool): True if no issues found (or all auto-corrected)
            - issues (list[dict]): Each issue has 'type', 'message', 'fix'
            - corrected (str): Auto-corrected filter expression
            - original (str): Original filter expression
    """
    issues = []
    corrected = filter_expr

    # Extract valid column names from schema
    valid_columns = []
    if schema:
        valid_columns = [
            col["name"] for col in schema.get("columns", [])
            if "name" in col
        ]

    # 1. Check forbidden SQL-like patterns
    for rule in FORBIDDEN_PATTERNS:
        if re.search(rule["pattern"], corrected, re.IGNORECASE):
            issues.append({
                "type": "forbidden_operator",
                "severity": "error",
                "message": rule["message"],
                "fix": rule["fix_hint"],
            })

    # 2. Auto-fix LIKE → Contains
    like_pattern = r"\[([^\]]+)\]\s+LIKE\s+'%([^']+)%'"
    like_match = re.search(like_pattern, corrected, re.IGNORECASE)
    if like_match:
        col_name = like_match.group(1)
        search_val = like_match.group(2)
        corrected = re.sub(
            like_pattern,
            f"Contains([{col_name}], '{search_val}')",
            corrected,
            flags=re.IGNORECASE,
        )

    # 3. Fix date formats
    for rule in DATE_WRONG_FORMATS:
        matches = list(re.finditer(rule["pattern"], corrected))
        if matches:
            for m in reversed(matches):  # Reverse to preserve positions
                issues.append({
                    "type": "date_format",
                    "severity": "error",
                    "message": rule["message"],
                    "fix": f"Corrigido automaticamente para formato #YYYY-MM-DD#",
                })
                corrected = corrected[:m.start()] + rule["fix"](m) + corrected[m.end():]

    # 4. Fix logical operators (AND/OR/NOT → and/or/not)
    for rule in LOGIC_OP_FIXES:
        if re.search(rule["pattern"], corrected):
            issues.append({
                "type": "logical_operator",
                "severity": "warning",
                "message": rule["message"],
                "fix": f"Corrigido automaticamente para '{rule['correct']}'",
            })
            corrected = re.sub(rule["pattern"], rule["correct"], corrected)

    # 5. Fix column accent issues
    # PRIORITY: schema (real column names) > ACCENT_FIXES (static dict)
    col_refs = _extract_column_refs(corrected)
    for col in col_refs:
        # Skip wildcard
        if col == "*":
            continue

        if valid_columns:
            # Schema available: use it as source of truth
            if col in valid_columns:
                continue  # Exact match — column is correct

            # Try fuzzy match against schema first
            suggestion = _fuzzy_match_column(col, valid_columns)
            if suggestion and suggestion != col:
                issues.append({
                    "type": "column_not_found",
                    "severity": "error",
                    "message": f"Coluna '[{col}]' → '[{suggestion}]' (corrigido via schema)",
                    "fix": f"Corrigido automaticamente para '[{suggestion}]'",
                })
                corrected = corrected.replace(f"[{col}]", f"[{suggestion}]")
            elif not suggestion:
                # Not in schema even with fuzzy — try ACCENT_FIXES as last resort
                if col in ACCENT_FIXES:
                    fixed = ACCENT_FIXES[col]
                    issues.append({
                        "type": "accent",
                        "severity": "warning",
                        "message": f"Coluna '{col}' → '{fixed}' (dicionário de acentos, não validado contra schema)",
                        "fix": f"Corrigido automaticamente",
                    })
                    corrected = corrected.replace(f"[{col}]", f"[{fixed}]")
                else:
                    issues.append({
                        "type": "column_not_found",
                        "severity": "error",
                        "message": f"Coluna '[{col}]' não encontrada na tabela. Colunas disponíveis: {', '.join(valid_columns[:10])}...",
                        "fix": None,
                    })
        else:
            # No schema: fall back to static ACCENT_FIXES
            if col in ACCENT_FIXES:
                fixed = ACCENT_FIXES[col]
                issues.append({
                    "type": "accent",
                    "severity": "error",
                    "message": f"Coluna '{col}' → '{fixed}' (acento incorreto)",
                    "fix": f"Corrigido automaticamente",
                })
                corrected = corrected.replace(f"[{col}]", f"[{fixed}]")

    # 6. Check for empty Contains
    empty_contains = re.findall(r"Contains\(\[[^\]]+\],\s*''\)", corrected)
    if empty_contains:
        issues.append({
            "type": "empty_search",
            "severity": "warning",
            "message": "Contains() com string vazia retorna todos os registros. Intencional?",
            "fix": None,
        })

    # 7. Check for potential injection (unescaped single quotes)
    # Count quotes outside of function calls
    in_quotes = False
    quote_count = 0
    for char in corrected:
        if char == "'":
            quote_count += 1
    if quote_count % 2 != 0:
        issues.append({
            "type": "syntax",
            "severity": "error",
            "message": "Número ímpar de aspas simples — possível erro de sintaxe",
            "fix": "Verificar aspas no filtro",
        })

    has_errors = any(i["severity"] == "error" and i["fix"] is None for i in issues)

    return {
        "valid": not has_errors,
        "issues": issues,
        "corrected": corrected,
        "original": filter_expr,
        "auto_fixed": corrected != filter_expr,
    }


def check_columns(
    columns: list[str],
    schema: Optional[dict] = None,
) -> dict:
    """
    Validate column names for accent correctness and existence.

    Args:
        columns: List of column names to validate.
        schema: Optional table schema from describe_table().

    Returns:
        dict with keys:
            - valid (bool): True if all columns are valid
            - issues (list[dict]): Problems found
            - corrected (list[str]): Corrected column names
    """
    issues = []
    corrected = []

    valid_columns = []
    if schema:
        valid_columns = [
            col["name"] for col in schema.get("columns", [])
            if "name" in col
        ]

    for col in columns:
        fixed_col = col

        if valid_columns:
            # Schema available: use as source of truth
            if col in valid_columns:
                pass  # Exact match, no fix needed
            else:
                suggestion = _fuzzy_match_column(col, valid_columns)
                if suggestion:
                    fixed_col = suggestion
                    issues.append({
                        "type": "column_not_found",
                        "severity": "error",
                        "column": col,
                        "message": f"'{col}' → '{suggestion}' (via schema)",
                    })
                elif col in ACCENT_FIXES:
                    # Fallback to static dict if schema has no match
                    fixed_col = ACCENT_FIXES[col]
                    issues.append({
                        "type": "accent",
                        "severity": "warning",
                        "column": col,
                        "message": f"'{col}' → '{fixed_col}' (dicionário, não validado contra schema)",
                    })
                else:
                    issues.append({
                        "type": "column_not_found",
                        "severity": "error",
                        "column": col,
                        "message": f"'{col}' não encontrada na tabela",
                    })
        else:
            # No schema: fall back to static ACCENT_FIXES
            if col in ACCENT_FIXES:
                fixed_col = ACCENT_FIXES[col]
                issues.append({
                    "type": "accent",
                    "severity": "error",
                    "column": col,
                    "message": f"'{col}' → '{fixed_col}'",
                })

        corrected.append(fixed_col)

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "corrected": corrected,
        "original": columns,
    }


def check_table_name(table_name: str) -> dict:
    """
    Validate and auto-correct a table name.

    Args:
        table_name: Table name to validate.

    Returns:
        dict with corrected name and any issues.
    """
    issues = []
    corrected = table_name

    if table_name in TABLE_FIXES:
        corrected = TABLE_FIXES[table_name]
        issues.append({
            "type": "table_name",
            "severity": "warning",
            "message": f"Tabela '{table_name}' → '{corrected}'",
        })

    return {
        "valid": True,
        "corrected": corrected,
        "original": table_name,
        "issues": issues,
    }


def check_upsert(
    data: any,
    schema: Optional[dict] = None,
) -> dict:
    """
    Validate upsert payload against TeamDesk gotchas.

    Args:
        data: The upsert payload (should be a list of dicts).
        schema: Optional table schema.

    Returns:
        dict with validation results.
    """
    issues = []

    # Gotcha #2: Body must be array
    if isinstance(data, dict):
        issues.append({
            "type": "upsert_format",
            "severity": "error",
            "message": "Upsert body DEVE ser array [{...}], não objeto {...}",
            "fix": "Envolvido automaticamente em array",
        })
        data = [data]

    if not isinstance(data, list):
        issues.append({
            "type": "upsert_format",
            "severity": "error",
            "message": f"Upsert body deve ser list, recebeu {type(data).__name__}",
            "fix": None,
        })
        return {"valid": False, "issues": issues, "corrected": data}

    # Check each record
    corrected_records = []
    valid_columns = []
    if schema:
        valid_columns = [
            col["name"] for col in schema.get("columns", [])
            if "name" in col
        ]

    for i, record in enumerate(data):
        if not isinstance(record, dict):
            issues.append({
                "type": "upsert_format",
                "severity": "error",
                "message": f"Registro [{i}] não é um objeto dict",
                "fix": None,
            })
            corrected_records.append(record)
            continue

        corrected_record = {}
        for key, value in record.items():
            corrected_key = key

            if valid_columns:
                # Schema available: use as source of truth
                if key in valid_columns:
                    pass  # Exact match
                else:
                    suggestion = _fuzzy_match_column(key, valid_columns)
                    if suggestion:
                        corrected_key = suggestion
                        issues.append({
                            "type": "column_not_found",
                            "severity": "error",
                            "message": f"Registro [{i}]: campo '{key}' → '{suggestion}' (via schema)",
                        })
                    elif key in ACCENT_FIXES:
                        corrected_key = ACCENT_FIXES[key]
                        issues.append({
                            "type": "accent",
                            "severity": "warning",
                            "message": f"Registro [{i}]: campo '{key}' → '{corrected_key}' (dicionário)",
                        })
            else:
                # No schema: fall back to ACCENT_FIXES
                if key in ACCENT_FIXES:
                    corrected_key = ACCENT_FIXES[key]
                    issues.append({
                        "type": "accent",
                        "severity": "error",
                        "message": f"Registro [{i}]: campo '{key}' → '{corrected_key}'",
                    })

            # Gotcha #23: Scientific notation in small floats
            if isinstance(value, float) and value != 0 and abs(value) < 0.0001:
                formatted = f"{value:.10f}".rstrip("0").rstrip(".")
                issues.append({
                    "type": "scientific_notation",
                    "severity": "warning",
                    "message": f"Registro [{i}]: valor {value} pode ser serializado como notação científica. Usar string '{formatted}'",
                })
                value = formatted

            corrected_record[corrected_key] = value

        corrected_records.append(corrected_record)

    has_errors = any(i["severity"] == "error" and i.get("fix") is None for i in issues)

    return {
        "valid": not has_errors,
        "issues": issues,
        "corrected": corrected_records,
        "original": data,
    }


def broaden_filter(filter_expr: str) -> list[dict]:
    """
    Generate progressively broader filter variants for self-correction.
    Used when a query returns 0 results to automatically retry with
    looser conditions.

    Strategies (in order):
        1. exact_to_contains: [Col] = 'val' → Contains([Col], 'val')
        2. widen_dates: expand date range by ±30 days
        3. remove_last_clause: drop the last 'and' condition
        4. no_filter: diagnostic query (confirms table has data)

    Args:
        filter_expr: The original filter that returned 0 results.

    Returns:
        list of dicts, each with:
            - filter (str|None): broadened filter (None = no filter)
            - strategy (str): strategy name
            - description (str): human-readable explanation
            - is_diagnostic (bool): True if just checking table has data
    """
    suggestions = []

    # Strategy 1: Convert exact match to Contains (partial search)
    exact_matches = list(re.finditer(
        r"\[([^\]]+)\]\s*=\s*'([^']+)'", filter_expr
    ))
    if exact_matches and "Contains(" not in filter_expr:
        new_filter = filter_expr
        for m in reversed(exact_matches):
            col = m.group(1)
            val = m.group(2)
            new_filter = (
                new_filter[:m.start()]
                + f"Contains([{col}], '{val}')"
                + new_filter[m.end():]
            )
        if new_filter != filter_expr:
            suggestions.append({
                "filter": new_filter,
                "strategy": "exact_to_contains",
                "description": "Convertido match exato (=) para busca parcial (Contains)",
                "is_diagnostic": False,
            })

    # Strategy 2: Widen date range by ±30 days
    date_ge = re.search(r">=\s*#(\d{4})-(\d{2})-(\d{2})#", filter_expr)
    date_le = re.search(r"<=\s*#(\d{4})-(\d{2})-(\d{2})#", filter_expr)
    if date_ge or date_le:
        from datetime import datetime, timedelta
        new_filter = filter_expr
        try:
            if date_ge:
                d = datetime(int(date_ge.group(1)), int(date_ge.group(2)), int(date_ge.group(3)))
                wider = (d - timedelta(days=30)).strftime("%Y-%m-%d")
                new_filter = new_filter.replace(
                    f"#{date_ge.group(1)}-{date_ge.group(2)}-{date_ge.group(3)}#",
                    f"#{wider}#",
                    1,
                )
            if date_le:
                d = datetime(int(date_le.group(1)), int(date_le.group(2)), int(date_le.group(3)))
                wider = (d + timedelta(days=30)).strftime("%Y-%m-%d")
                new_filter = new_filter.replace(
                    f"#{date_le.group(1)}-{date_le.group(2)}-{date_le.group(3)}#",
                    f"#{wider}#",
                    1,
                )
            if new_filter != filter_expr:
                suggestions.append({
                    "filter": new_filter,
                    "strategy": "widen_dates",
                    "description": "Ampliado range de datas em ±30 dias",
                    "is_diagnostic": False,
                })
        except (ValueError, IndexError):
            pass

    # Strategy 3: Remove last AND clause
    parts = re.split(r"\s+and\s+", filter_expr, flags=re.IGNORECASE)
    if len(parts) > 1:
        reduced = " and ".join(parts[:-1])
        removed = parts[-1].strip()
        suggestions.append({
            "filter": reduced,
            "strategy": "remove_last_clause",
            "description": f"Removida última condição: '{removed}'",
            "is_diagnostic": False,
        })

    # Strategy 4 (diagnostic): No filter
    suggestions.append({
        "filter": None,
        "strategy": "no_filter",
        "description": "Consulta sem filtro (diagnóstico: tabela tem dados?)",
        "is_diagnostic": True,
    })

    return suggestions


def check_all(
    table_name: str,
    filter_expr: Optional[str] = None,
    columns: Optional[list[str]] = None,
    upsert_data: Optional[any] = None,
    schema: Optional[dict] = None,
) -> dict:
    """
    Run all checks at once. Convenience wrapper.

    Args:
        table_name: Table name to query.
        filter_expr: Optional filter expression.
        columns: Optional list of column names.
        upsert_data: Optional upsert payload.
        schema: Optional schema from describe_table().

    Returns:
        dict with all validation results combined.
    """
    results = {
        "table": check_table_name(table_name),
        "all_valid": True,
        "total_issues": 0,
        "total_auto_fixed": 0,
    }

    if filter_expr:
        results["filter"] = check_filter(filter_expr, schema)
    if columns:
        results["columns"] = check_columns(columns, schema)
    if upsert_data is not None:
        results["upsert"] = check_upsert(upsert_data, schema)

    # Aggregate
    all_issues = results["table"]["issues"][:]
    for key in ("filter", "columns", "upsert"):
        if key in results:
            all_issues.extend(results[key]["issues"])

    results["total_issues"] = len(all_issues)
    results["total_auto_fixed"] = sum(
        1 for i in all_issues if i.get("fix") is not None
    )
    results["all_valid"] = all(
        results.get(k, {}).get("valid", True)
        for k in ("table", "filter", "columns", "upsert")
    )

    return results
