"""Regex-based vulnerability pattern scanner for CodeSentinel.

Used by the Security Agent to scan source files for common vulnerability
patterns. Loads patterns dynamically from the SQLite vulnerability knowledge
base (via MCP). Falls back to a built-in static set if the DB is empty.

Covers CWE Top 25 + OWASP Top 10 categories including:
- Hardcoded secrets (CWE-798)
- SQL injection (CWE-89)
- Command injection (CWE-78)
- Code injection / eval/exec (CWE-95)
- XSS (CWE-79)
- Path traversal (CWE-22)
- Insecure deserialization (CWE-502)
- SSRF (CWE-918)
- XXE (CWE-611)
- Weak cryptography (CWE-327)
- Insecure TLS (CWE-295)
- And more...
"""

import json
import re
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

# --- Static Fallback Patterns (used if DB is empty) ---
VULNERABILITY_PATTERNS: dict[str, list[dict]] = {
    "hardcoded_secret": [
        {
            "pattern": r"""(?i)(api[_-]?key|secret[_-]?key|password|token|auth[_-]?token)\s*[=:]\s*['"][A-Za-z0-9+/=!@#$%^&*]{8,}['"]""",
            "cwe_id": "CWE-798",
            "severity": "critical",
            "description": "Hardcoded secret or credential found",
        },
        {
            "pattern": r"""(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['"].+['"]""",
            "cwe_id": "CWE-798",
            "severity": "critical",
            "description": "Hardcoded AWS credential",
        },
        {
            "pattern": r"""(?i)(db[_-]?password|database[_-]?password|mysql[_-]?password|postgres[_-]?password)\s*[=:]\s*['"].+['"]""",
            "cwe_id": "CWE-798",
            "severity": "critical",
            "description": "Hardcoded database password",
        },
    ],
    "sql_injection": [
        {
            "pattern": r"""f['"].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s.*?\{.*?\}.*?['"]""",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "description": "SQL query with f-string interpolation — potential SQL injection",
        },
        {
            "pattern": r"""['"].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s.*?['"].*?\.format\(""",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "description": "SQL query using .format() — potential SQL injection",
        },
        {
            "pattern": r"""['"].*?(SELECT|INSERT|UPDATE|DELETE)\s.*?['"].*?\+\s*\w+""",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "description": "SQL query with string concatenation — potential SQL injection",
        },
    ],
    "command_injection": [
        {
            "pattern": r"""os\.system\s*\(.*?(\+|\.format|{)""",
            "cwe_id": "CWE-78",
            "severity": "critical",
            "description": "os.system() with dynamic input — command injection risk",
        },
        {
            "pattern": r"""subprocess\.(call|run|Popen)\s*\(.*?shell\s*=\s*True""",
            "cwe_id": "CWE-78",
            "severity": "critical",
            "description": "subprocess with shell=True — command injection risk",
        },
        {
            "pattern": r"""os\.popen\s*\(""",
            "cwe_id": "CWE-78",
            "severity": "high",
            "description": "os.popen() usage — potential command injection",
        },
    ],
    "path_traversal": [
        {
            "pattern": r"""open\s*\(.*?(\+|\.format|{).*?\)""",
            "cwe_id": "CWE-22",
            "severity": "high",
            "description": "File open with dynamic path — potential path traversal",
        },
        {
            "pattern": r"""Path\s*\(.*?(request|user_input|param)""",
            "cwe_id": "CWE-22",
            "severity": "high",
            "description": "Path constructed from user input — potential path traversal",
        },
    ],
    "insecure_deserialization": [
        {
            "pattern": r"""pickle\.loads?\s*\(""",
            "cwe_id": "CWE-502",
            "severity": "high",
            "description": "pickle.load(s) on potentially untrusted data — insecure deserialization",
        },
        {
            "pattern": r"""yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)""",
            "cwe_id": "CWE-502",
            "severity": "high",
            "description": "yaml.load() without SafeLoader — insecure deserialization",
        },
    ],
}


def _load_patterns_from_db(
    categories: list[str] | None = None,
    language: str = "python",
) -> list[dict] | None:
    """Load vulnerability patterns from the SQLite knowledge base via MCP.

    Falls back to None if the database table is empty or doesn't exist,
    allowing the caller to use the static fallback patterns.

    Args:
        categories: Optional category filter list.
        language: Target language (default: "python").

    Returns:
        List of pattern dicts from DB, or None if DB is unavailable/empty.
    """
    try:
        from src.db.queries import get_vulnerability_patterns, get_pattern_count

        if get_pattern_count() == 0:
            return None

        if categories:
            all_patterns = []
            for cat in categories:
                all_patterns.extend(get_vulnerability_patterns(category=cat, language=language))
            return all_patterns if all_patterns else None
        else:
            patterns = get_vulnerability_patterns(language=language)
            return patterns if patterns else None

    except Exception:
        return None


class PatternScannerInput(BaseModel):
    """Input schema for the pattern scanner tool."""

    file_path: str = Field(
        ...,
        description="Absolute or relative path to a source file to scan for vulnerability patterns.",
    )
    categories: list[str] | None = Field(
        default=None,
        description=(
            "Optional list of vulnerability categories to scan for. "
            "Loads categories from the vulnerability knowledge base. "
            "Falls back to built-in patterns if the DB is empty."
        ),
    )


@tool(args_schema=PatternScannerInput)
def pattern_scanner(file_path: str, categories: list[str] | None = None) -> str:
    """Scan a source file for vulnerability patterns from the CWE/OWASP knowledge base.

    Loads detection patterns dynamically from the SQLite vulnerability database
    (populated with CWE Top 25 + OWASP Top 10 rules). Falls back to a built-in
    static pattern set if the database is empty.

    The tool returns line-level matches with severity, CWE IDs, OWASP references,
    attack vectors, and remediation guidance.

    Args:
        file_path: Path to the source file to scan.
        categories: Optional list of categories to scan. Scans all if not specified.

    Returns:
        JSON string with list of vulnerability matches found.

    Raises:
        FileNotFoundError: If the target file does not exist.
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return json.dumps({"status": "error", "error": f"File not found: {file_path}", "tool": "pattern_scanner"})

        source = path.read_text(encoding="utf-8")
        lines = source.split("\n")

        # Try loading patterns from the vulnerability knowledge base
        db_patterns = _load_patterns_from_db(categories=categories)
        pattern_source = "database"

        if db_patterns:
            # Use DB patterns — each dict has keys: pattern, category, severity, cwe_id, etc.
            matches = _scan_with_db_patterns(lines, db_patterns, file_path)
        else:
            # Fall back to static patterns
            pattern_source = "static_fallback"
            matches = _scan_with_static_patterns(lines, categories, file_path)

        # Deduplicate: same file + line + category = one match
        seen: set[str] = set()
        unique_matches: list[dict] = []
        for m in matches:
            key = f"{m['file']}:{m['line_start']}:{m['category']}"
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)

        return json.dumps(
            {
                "status": "success",
                "data": {
                    "matches": unique_matches,
                    "total_matches": len(unique_matches),
                    "categories_scanned": categories or _get_all_categories(db_patterns),
                    "pattern_source": pattern_source,
                    "total_patterns_loaded": len(db_patterns) if db_patterns else sum(
                        len(v) for v in VULNERABILITY_PATTERNS.values()
                    ),
                },
                "metadata": {"tool": "pattern_scanner", "file": file_path},
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "pattern_scanner"})


def _scan_with_db_patterns(
    lines: list[str], patterns: list[dict], file_path: str,
) -> list[dict]:
    """Scan source lines using patterns loaded from the database.

    Args:
        lines: Source code lines.
        patterns: Pattern dicts from the vulnerability_patterns table.
        file_path: Path to the file being scanned.

    Returns:
        List of match dicts.
    """
    matches: list[dict] = []

    for pdef in patterns:
        regex = pdef.get("pattern", "")
        try:
            compiled = re.compile(regex, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue

        for i, line in enumerate(lines, start=1):
            if compiled.search(line):
                matches.append({
                    "category": pdef.get("category", "unknown"),
                    "subcategory": pdef.get("subcategory"),
                    "severity": pdef.get("severity", "medium"),
                    "cwe_id": pdef.get("cwe_id"),
                    "owasp_id": pdef.get("owasp_id"),
                    "description": pdef.get("description", ""),
                    "attack_vector": pdef.get("attack_vector"),
                    "remediation": pdef.get("remediation"),
                    "file": file_path,
                    "line_start": i,
                    "line_end": i,
                    "matched_content": line.strip()[:200],
                })

    return matches


def _scan_with_static_patterns(
    lines: list[str],
    categories: list[str] | None,
    file_path: str,
) -> list[dict]:
    """Scan source lines using the built-in static pattern dict.

    Args:
        lines: Source code lines.
        categories: Optional category filter.
        file_path: Path to the file being scanned.

    Returns:
        List of match dicts.
    """
    scan_categories = categories or list(VULNERABILITY_PATTERNS.keys())
    matches: list[dict] = []

    for category in scan_categories:
        if category not in VULNERABILITY_PATTERNS:
            continue

        for pattern_def in VULNERABILITY_PATTERNS[category]:
            regex = pattern_def["pattern"]
            try:
                compiled = re.compile(regex, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue

            for i, line in enumerate(lines, start=1):
                if compiled.search(line):
                    matches.append({
                        "category": category,
                        "severity": pattern_def["severity"],
                        "cwe_id": pattern_def["cwe_id"],
                        "description": pattern_def["description"],
                        "file": file_path,
                        "line_start": i,
                        "line_end": i,
                        "matched_content": line.strip()[:200],
                    })

    return matches


def _get_all_categories(db_patterns: list[dict] | None) -> list[str]:
    """Extract unique category names from pattern list.

    Args:
        db_patterns: Patterns from DB or None.

    Returns:
        Sorted list of unique category names.
    """
    if db_patterns:
        return sorted({p.get("category", "unknown") for p in db_patterns})
    return list(VULNERABILITY_PATTERNS.keys())
