# Skill: Tool Development for CodeSentinel

## Principle

Tools are the bridge between agents and the real world. An agent without tools is just a text generator. Every tool in CodeSentinel follows strict conventions for type safety, documentation, and error handling — the assignment rubric allocates 20% to individual tool quality.

## Tool Template (Mandatory Pattern)

```python
"""Module docstring explaining the tool's purpose."""

import json
import subprocess
from pathlib import Path
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field


class ToolNameInput(BaseModel):
    """Input schema for tool_name with full validation."""

    param_one: str = Field(
        ...,
        description="What this parameter represents and its expected format",
        examples=["src/main.py"]
    )
    param_two: int = Field(
        default=10,
        description="Optional parameter with sensible default",
        ge=1,
        le=100
    )


@tool(args_schema=ToolNameInput)
def tool_name(param_one: str, param_two: int = 10) -> str:
    """One-line summary of the tool's function.

    Extended description: what the tool does, when an agent should call it,
    and what the output looks like. This docstring is fed to the LLM so
    it must be clear enough for the model to know WHEN and HOW to use it.

    Args:
        param_one: Full description with format expectations.
        param_two: Full description with default behavior.

    Returns:
        JSON string with structure:
        {
            "status": "success" | "error",
            "data": { ... tool-specific output ... },
            "metadata": { "tool": "tool_name", "params_used": { ... } }
        }

    Raises:
        FileNotFoundError: When the specified file path does not exist.
        subprocess.CalledProcessError: When a shell command fails.
    """
    try:
        # --- Implementation ---
        result = _internal_logic(param_one, param_two)

        return json.dumps({
            "status": "success",
            "data": result,
            "metadata": {"tool": "tool_name", "params_used": {"param_one": param_one}}
        }, indent=2)

    except FileNotFoundError as e:
        return json.dumps({
            "status": "error",
            "error": f"File not found: {e}",
            "tool": "tool_name"
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": f"Unexpected error: {type(e).__name__}: {e}",
            "tool": "tool_name"
        })
```

---

## Tool 1: AST Parser (`src/tools/ast_parser.py`)

**Used by:** Code Quality Agent
**Purpose:** Parse Python source files into structured AST data (function signatures, class info, complexity metrics) so the LLM can reason about structure without reading raw code.

```python
"""AST parsing tool for extracting structural code metrics."""

import ast
import json
from pathlib import Path
from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field


class ASTParserInput(BaseModel):
    """Input schema for the AST parser tool."""

    file_path: str = Field(
        ...,
        description="Absolute or relative path to a Python source file to analyze. Must end in .py"
    )
    include_complexity: bool = Field(
        default=True,
        description="Whether to calculate cyclomatic complexity for each function"
    )


def _calculate_complexity(node: ast.AST) -> int:
    """Calculate cyclomatic complexity of an AST node.

    Counts decision points: if, elif, for, while, except, with,
    assert, and, or, ternary expressions.

    Args:
        node: An AST node (typically a FunctionDef or AsyncFunctionDef).

    Returns:
        Integer complexity score. 1 = linear, >10 = complex.
    """
    complexity = 1  # Base complexity
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp)):
            complexity += 1
        elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
            complexity += 1
        elif isinstance(child, ast.ExceptHandler):
            complexity += 1
        elif isinstance(child, ast.With):
            complexity += 1
        elif isinstance(child, ast.Assert):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
    return complexity


def _get_max_nesting_depth(node: ast.AST, current_depth: int = 0) -> int:
    """Calculate the maximum nesting depth within a function.

    Args:
        node: AST node to analyze.
        current_depth: Current nesting level (used in recursion).

    Returns:
        Maximum nesting depth found.
    """
    max_depth = current_depth
    nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor)

    for child in ast.iter_child_nodes(node):
        if isinstance(child, nesting_nodes):
            child_depth = _get_max_nesting_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
        else:
            child_depth = _get_max_nesting_depth(child, current_depth)
            max_depth = max(max_depth, child_depth)

    return max_depth


@tool(args_schema=ASTParserInput)
def parse_ast_tool(file_path: str, include_complexity: bool = True) -> str:
    """Parse a Python file and extract structural metrics for code quality analysis.

    Use this tool to analyze a Python source file's structure without reading raw code.
    Returns function signatures, class definitions, line counts, cyclomatic complexity,
    nesting depth, and detected imports. Call this BEFORE making any claims about code
    structure or quality.

    Args:
        file_path: Path to the Python file to analyze.
        include_complexity: Whether to compute cyclomatic complexity per function.

    Returns:
        JSON string containing:
        - functions: list of {name, line_start, line_end, args, returns, complexity, max_nesting, decorators}
        - classes: list of {name, line_start, line_end, methods_count, bases, total_lines}
        - imports: list of imported module names
        - file_metrics: {total_lines, blank_lines, comment_lines, code_lines}
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return json.dumps({"status": "error", "error": f"File not found: {file_path}"})
        if path.suffix != ".py":
            return json.dumps({"status": "error", "error": f"Not a Python file: {file_path}"})

        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=file_path)

        lines = source.split("\n")
        total_lines = len(lines)
        blank_lines = sum(1 for l in lines if not l.strip())
        comment_lines = sum(1 for l in lines if l.strip().startswith("#"))

        functions = []
        classes = []
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info = {
                    "name": node.name,
                    "line_start": node.lineno,
                    "line_end": node.end_lineno or node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "returns": ast.dump(node.returns) if node.returns else None,
                    "has_docstring": (
                        isinstance(node.body[0], ast.Expr) and
                        isinstance(node.body[0].value, (ast.Str, ast.Constant))
                    ) if node.body else False,
                    "decorators": [ast.dump(d) for d in node.decorator_list],
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                }
                func_info["line_count"] = func_info["line_end"] - func_info["line_start"] + 1

                if include_complexity:
                    func_info["cyclomatic_complexity"] = _calculate_complexity(node)
                    func_info["max_nesting_depth"] = _get_max_nesting_depth(node)

                functions.append(func_info)

            elif isinstance(node, ast.ClassDef):
                methods = [n for n in ast.walk(node) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                classes.append({
                    "name": node.name,
                    "line_start": node.lineno,
                    "line_end": node.end_lineno or node.lineno,
                    "methods_count": len(methods),
                    "bases": [ast.dump(b) for b in node.bases],
                    "total_lines": (node.end_lineno or node.lineno) - node.lineno + 1,
                })

            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                else:
                    imports.append(f"{node.module}.{node.names[0].name}" if node.module else node.names[0].name)

        return json.dumps({
            "status": "success",
            "data": {
                "functions": functions,
                "classes": classes,
                "imports": list(set(imports)),
                "file_metrics": {
                    "total_lines": total_lines,
                    "blank_lines": blank_lines,
                    "comment_lines": comment_lines,
                    "code_lines": total_lines - blank_lines - comment_lines,
                }
            },
            "metadata": {"tool": "ast_parser", "file": file_path}
        }, indent=2)

    except SyntaxError as e:
        return json.dumps({"status": "error", "error": f"Syntax error in {file_path}: {e}", "tool": "ast_parser"})
    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "ast_parser"})
```

---

## Tool 2: Git Analyzer (`src/tools/git_analyzer.py`)

**Used by:** Orchestrator (for planning) + Security Agent (for history scanning)

Key operations:
- `get_repo_info`: Languages, file count, last commit
- `get_recently_changed_files`: Files changed in last N commits (hotspot detection)
- `search_git_history_for_secrets`: Check if patterns were ever committed
- `get_file_blame`: Who last modified each line (for attribution)

```python
@tool(args_schema=GitAnalyzerInput)
def git_analyzer(repo_path: str, operation: str, params: dict | None = None) -> str:
    """Analyze a Git repository's history, structure, and change patterns.

    Operations:
    - "repo_info": Get repo metadata (languages, file count, branches)
    - "recent_changes": Get files changed in last N commits (default: 10)
    - "search_history": Search all commits for a regex pattern (e.g., secrets)
    - "file_blame": Get blame info for a specific file
    - "file_diff": Get diff for a specific file across last N commits
    """
```

---

## Tool 3: Pattern Scanner (`src/tools/pattern_scanner.py`)

**Used by:** Security Agent

Scans files for vulnerability patterns using regex:

```python
VULNERABILITY_PATTERNS = {
    "hardcoded_secret": [
        r"""(?i)(api[_-]?key|secret|password|token|auth)\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
        r"""(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['"].+['"]""",
    ],
    "sql_injection": [
        r"""f['\"].*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?\{.*?\}.*?['\"]""",
        r"""\.format\(.*?\).*?(SELECT|INSERT|UPDATE|DELETE)""",
        r"""['\"]\s*\+\s*\w+\s*\+\s*['\"].*?(WHERE|AND|OR)""",
    ],
    "command_injection": [
        r"""os\.system\s*\(.*?\+""",
        r"""subprocess\.(call|run|Popen)\s*\(.*?(shell\s*=\s*True)""",
    ],
    "path_traversal": [
        r"""open\s*\(.*?\+""",
        r"""Path\s*\(.*?request\.""",
    ],
    "insecure_deserialization": [
        r"""pickle\.loads?\s*\(""",
        r"""yaml\.load\s*\((?!.*Loader)""",
    ],
}
```

---

## Tool 4: Report Generator (`src/tools/report_generator.py`)

**Used by:** Orchestrator (final step)

Compiles all findings into a structured Markdown report and persists to SQLite:

```python
@tool(args_schema=ReportGeneratorInput)
def generate_report(
    repo_path: str,
    code_quality_findings: str,
    security_findings: str,
    refactoring_plan: str,
    output_path: str
) -> str:
    """Generate a comprehensive Markdown audit report and persist findings to SQLite.

    Creates a structured report with:
    - Executive summary with severity counts
    - Code quality findings sorted by severity
    - Security vulnerabilities with CWE references
    - Prioritized refactoring plan with before/after snippets
    - Historical comparison (if previous audits exist in DB)
    """
```

## Tool Assignment Matrix (for Individual Contributions)

| Student | Agent Owned | Tool Owned | Tests Owned |
|---------|-------------|-----------|-------------|
| Student 1 | Orchestrator | git_analyzer.py | test_orchestrator.py |
| Student 2 | Code Quality | ast_parser.py | test_code_quality.py |
| Student 3 | Security | pattern_scanner.py | test_security.py |
| Student 4 | Refactoring | report_generator.py | test_refactoring.py |