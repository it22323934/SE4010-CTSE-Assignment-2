"""AST parsing tool for extracting structural code metrics.

Used by the Code Quality Agent to analyze Python source files without
reading raw code. Extracts functions, classes, complexity, nesting depth,
and import information.
"""

import ast
import json
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field


class ASTParserInput(BaseModel):
    """Input schema for the AST parser tool."""

    file_path: str = Field(
        ...,
        description="Absolute or relative path to a Python source file to analyze. Must end in .py",
    )
    include_complexity: bool = Field(
        default=True,
        description="Whether to calculate cyclomatic complexity for each function",
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
    complexity = 1
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


def _check_bare_excepts(tree: ast.AST) -> list[dict]:
    """Find bare except clauses in the AST.

    Args:
        tree: Parsed AST tree.

    Returns:
        List of dicts with line info for bare excepts.
    """
    bare_excepts = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            bare_excepts.append({
                "line": node.lineno,
                "end_line": node.end_lineno or node.lineno,
            })
    return bare_excepts


def _find_unused_imports(tree: ast.AST, source: str) -> list[dict]:
    """Detect imports that are never referenced in the module body.

    Args:
        tree: Parsed AST tree.
        source: Raw source code string.

    Returns:
        List of dicts with import name and line number.
    """
    imported_names: dict[str, int] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imported_names[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                imported_names[name] = node.lineno

    # Check which names are actually used (simple heuristic: appear elsewhere in source)
    unused = []
    for name, line in imported_names.items():
        # Count occurrences — if only 1 (the import itself), it's unused
        occurrences = source.count(name)
        if occurrences <= 1:
            unused.append({"name": name, "line": line})

    return unused


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
        JSON string with functions, classes, imports, file_metrics, bare_excepts, unused_imports.

    Raises:
        FileNotFoundError: If the target file does not exist.
        SyntaxError: If the Python file has syntax errors.
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return json.dumps({"status": "error", "error": f"File not found: {file_path}", "tool": "ast_parser"})
        if path.suffix != ".py":
            return json.dumps({"status": "error", "error": f"Not a Python file: {file_path}", "tool": "ast_parser"})

        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=file_path)

        lines = source.split("\n")
        total_lines = len(lines)
        blank_lines = sum(1 for line in lines if not line.strip())
        comment_lines = sum(1 for line in lines if line.strip().startswith("#"))

        functions: list[dict] = []
        classes: list[dict] = []
        imports: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info: dict = {
                    "name": node.name,
                    "line_start": node.lineno,
                    "line_end": node.end_lineno or node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "returns": ast.dump(node.returns) if node.returns else None,
                    "has_docstring": (
                        isinstance(node.body[0], ast.Expr)
                        and isinstance(node.body[0].value, (ast.Constant,))
                    )
                    if node.body
                    else False,
                    "decorators": [ast.dump(d) for d in node.decorator_list],
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                }
                func_info["line_count"] = func_info["line_end"] - func_info["line_start"] + 1

                if include_complexity:
                    func_info["cyclomatic_complexity"] = _calculate_complexity(node)
                    func_info["max_nesting_depth"] = _get_max_nesting_depth(node)

                functions.append(func_info)

            elif isinstance(node, ast.ClassDef):
                methods = [
                    n
                    for n in ast.walk(node)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
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
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}" if module else alias.name)

        bare_excepts = _check_bare_excepts(tree)
        unused_imports = _find_unused_imports(tree, source)

        return json.dumps(
            {
                "status": "success",
                "data": {
                    "functions": functions,
                    "classes": classes,
                    "imports": list(set(imports)),
                    "bare_excepts": bare_excepts,
                    "unused_imports": unused_imports,
                    "file_metrics": {
                        "total_lines": total_lines,
                        "blank_lines": blank_lines,
                        "comment_lines": comment_lines,
                        "code_lines": total_lines - blank_lines - comment_lines,
                    },
                },
                "metadata": {"tool": "ast_parser", "file": file_path},
            },
            indent=2,
        )

    except SyntaxError as e:
        return json.dumps({"status": "error", "error": f"Syntax error in {file_path}: {e}", "tool": "ast_parser"})
    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "ast_parser"})
