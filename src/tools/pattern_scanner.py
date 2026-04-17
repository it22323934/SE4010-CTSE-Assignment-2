"""Regex-based vulnerability pattern scanner for CodeSentinel.

Used by the Security Agent to scan source files for common vulnerability
patterns: hardcoded secrets, SQL injection, command injection, path traversal,
and insecure deserialization.
"""

import json
import re
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

# --- Vulnerability Pattern Definitions ---
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
            "Options: hardcoded_secret, sql_injection, command_injection, "
            "path_traversal, insecure_deserialization. Scans all if not specified."
        ),
    )


@tool(args_schema=PatternScannerInput)
def pattern_scanner(file_path: str, categories: list[str] | None = None) -> str:
    """Scan a source file for common vulnerability patterns using regex matching.

    Use this tool to detect security vulnerabilities in source code files.
    Scans for hardcoded secrets, SQL injection vectors, command injection,
    path traversal, and insecure deserialization patterns.

    The tool returns line-level matches with severity, CWE IDs, and descriptions.
    Call this on each file the Security Agent needs to analyze.

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
                            "matched_content": line.strip()[:200],  # Truncate for safety
                        })

        return json.dumps(
            {
                "status": "success",
                "data": {
                    "matches": matches,
                    "total_matches": len(matches),
                    "categories_scanned": scan_categories,
                },
                "metadata": {"tool": "pattern_scanner", "file": file_path},
            },
            indent=2,
        )

    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "pattern_scanner"})
