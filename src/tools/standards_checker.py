"""Language-specific coding standards checker.

Encodes best practices from the community (Python PEP 8/20, JavaScript clean code,
React patterns, TypeScript do's and don'ts) as deterministic regex-based rules.
Each rule maps to a specific best-practice source.

Used by the Code Quality Agent to flag coding standard violations.
"""

import json
import re
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Rule definitions per language — sourced from best-coding-practices repo
# ---------------------------------------------------------------------------

PYTHON_RULES: list[dict] = [
    {
        "id": "PY-NAMING-FUNC",
        "pattern": r"def\s+([A-Z][a-zA-Z]+)\s*\(",
        "category": "naming_convention",
        "severity": "medium",
        "description": "Function `{match}` uses PascalCase instead of snake_case (PEP 8).",
        "suggestion": "Rename to snake_case: `{fix}`.",
        "source": "PEP 8 / Python BOBP Guide",
        "extract_group": 1,
        "fix_fn": "to_snake_case",
    },
    {
        "id": "PY-NAMING-VAR",
        "pattern": r"^\s+([a-z][a-zA-Z]+[A-Z][a-zA-Z]*)\s*=\s*(?!.*lambda)",
        "category": "naming_convention",
        "severity": "low",
        "description": "Variable `{match}` uses camelCase instead of snake_case (PEP 8).",
        "suggestion": "Rename to snake_case: `{fix}`.",
        "source": "PEP 8 / Python BOBP Guide",
        "extract_group": 1,
        "fix_fn": "to_snake_case",
    },
    {
        "id": "PY-IMPORT-STAR",
        "pattern": r"^from\s+\S+\s+import\s+\*",
        "category": "import_style",
        "severity": "high",
        "description": "Wildcard import `from ... import *` pollutes namespace and hides dependencies.",
        "suggestion": "Import specific symbols or the module itself.",
        "source": "PEP 8 / Python BOBP Guide",
    },
    {
        "id": "PY-MUTABLE-DEFAULT",
        "pattern": r"def\s+\w+\s*\([^)]*(?::\s*\w+\s*)?=\s*(\[\]|\{\}|\bset\(\))",
        "category": "anti_pattern",
        "severity": "high",
        "description": "Mutable default argument detected. Default mutable objects are shared across calls.",
        "suggestion": "Use `None` as default and create the mutable inside the function body.",
        "source": "Common Python anti-patterns / DeepSource",
    },
    {
        "id": "PY-BARE-EXCEPT",
        "pattern": r"^\s*except\s*:",
        "category": "error_handling",
        "severity": "medium",
        "description": "Bare `except:` catches all exceptions including SystemExit and KeyboardInterrupt.",
        "suggestion": "Catch specific exceptions: `except (ValueError, TypeError) as e:`.",
        "source": "PEP 8 / Python BOBP Guide",
    },
    {
        "id": "PY-PRINT-DEBUG",
        "pattern": r"^\s*print\s*\(",
        "category": "debug_code",
        "severity": "low",
        "description": "`print()` call found — use a proper logging framework in production code.",
        "suggestion": "Replace with `logging.info()` or `logging.debug()`.",
        "source": "Python Best Practices / Hitchhiker's Guide",
    },
    {
        "id": "PY-GLOBAL-VAR",
        "pattern": r"^\s*global\s+\w+",
        "category": "anti_pattern",
        "severity": "medium",
        "description": "Global variable mutation detected. Globals make code harder to test and reason about.",
        "suggestion": "Pass values as function arguments or use a class/config object.",
        "source": "Python BOBP Guide / Clean Code",
    },
    {
        "id": "PY-TYPE-COMPARE",
        "pattern": r"type\s*\(\s*\w+\s*\)\s*==",
        "category": "anti_pattern",
        "severity": "low",
        "description": "Use `isinstance()` instead of `type()` comparison for type checking.",
        "suggestion": "Replace `type(x) == Y` with `isinstance(x, Y)`.",
        "source": "PEP 8 / Common Python anti-patterns",
    },
    {
        "id": "PY-MAP-LAMBDA",
        "pattern": r"map\s*\(\s*lambda\s+",
        "category": "style",
        "severity": "low",
        "description": "Prefer list comprehension over `map(lambda ...)`.",
        "suggestion": "Use `[expr for x in iterable]` instead of `map(lambda x: expr, iterable)`.",
        "source": "Pythonic Code / BOBP Guide",
    },
    {
        "id": "PY-NESTED-WITH",
        "pattern": r"with\s+.*:\s*\n\s+with\s+",
        "category": "style",
        "severity": "low",
        "description": "Nested `with` statements can be combined into a single statement (Python 3.10+).",
        "suggestion": "Combine: `with open(a) as f1, open(b) as f2:`.",
        "source": "PEP 8 / Modern Python practices",
    },
    {
        "id": "PY-STRING-FORMAT",
        "pattern": r"[\"']\s*%\s*\(",
        "category": "style",
        "severity": "low",
        "description": "Old-style `%` string formatting detected. Prefer f-strings.",
        "suggestion": "Use f-strings: `f\"value: {var}\"` instead of `\"value: %s\" % var`.",
        "source": "PEP 498 / Modern Python practices",
    },
    {
        "id": "PY-RETURN-NONE",
        "pattern": r"return\s+None\s*$",
        "category": "style",
        "severity": "low",
        "description": "Explicit `return None` is unnecessary — Python returns None implicitly.",
        "suggestion": "Use bare `return` or remove the return statement.",
        "source": "PEP 8 / Python BOBP Guide",
    },
]

JS_TS_RULES: list[dict] = [
    {
        "id": "JS-VAR-DECL",
        "pattern": r"^\s*var\s+\w+",
        "category": "anti_pattern",
        "severity": "high",
        "description": "`var` declaration found — `var` has function-scoping issues and hoisting bugs.",
        "suggestion": "Use `const` for immutable bindings or `let` for mutable ones.",
        "source": "JavaScript Clean Coding Best Practices / ES6+",
    },
    {
        "id": "JS-EQ-LOOSE",
        "pattern": r"[^!=]==[^=]",
        "category": "anti_pattern",
        "severity": "medium",
        "description": "Loose equality `==` performs type coercion which causes subtle bugs.",
        "suggestion": "Use strict equality `===` instead.",
        "source": "JavaScript Best Practices / Clean Code",
    },
    {
        "id": "JS-CONSOLE-LOG",
        "pattern": r"^\s*console\.(log|debug|info|warn)\s*\(",
        "category": "debug_code",
        "severity": "low",
        "description": "`console.{method}()` left in code — remove before production.",
        "suggestion": "Remove debug logging or use a proper logging library.",
        "source": "JavaScript Clean Coding / React Best Practices",
    },
    {
        "id": "JS-CALLBACK-HELL",
        "pattern": r"\.then\s*\([^)]*\)\s*\.\s*then\s*\([^)]*\)\s*\.\s*then",
        "category": "anti_pattern",
        "severity": "medium",
        "description": "Deeply chained `.then()` calls (callback hell). Hard to read and debug.",
        "suggestion": "Refactor to use `async/await` syntax.",
        "source": "JavaScript Clean Coding Best Practices",
    },
    {
        "id": "JS-NESTED-TERNARY",
        "pattern": r"\?[^:]+:[^?]+\?[^:]+:",
        "category": "readability",
        "severity": "medium",
        "description": "Nested ternary expression found. Reduces readability significantly.",
        "suggestion": "Replace with `if/else` block or extract into a named function.",
        "source": "JavaScript Best Practices / Clean Code",
    },
    {
        "id": "JS-MAGIC-NUMBER",
        "pattern": r"(?:if|while|for|return|===?|!==?|[+\-*/])\s*(?<!['\"])\b(\d{2,})\b(?!['\"])",
        "category": "readability",
        "severity": "low",
        "description": "Magic number detected. Unnamed numeric literals reduce code readability.",
        "suggestion": "Extract into a named constant: `const MAX_RETRIES = {value};`.",
        "source": "JavaScript Clean Coding / Best Practices",
    },
    {
        "id": "JS-EMPTY-CATCH",
        "pattern": r"catch\s*\([^)]*\)\s*\{\s*\}",
        "category": "error_handling",
        "severity": "high",
        "description": "Empty `catch` block silently swallows errors.",
        "suggestion": "Log the error or re-throw it. Never swallow exceptions silently.",
        "source": "JavaScript Exception Handling Patterns",
    },
    {
        "id": "JS-TODO-FIXME",
        "pattern": r"(?://|/\*)\s*(TODO|FIXME|HACK|XXX)\b",
        "category": "todo_comment",
        "severity": "low",
        "description": "{tag} comment indicates unfinished or problematic code.",
        "suggestion": "Address the {tag} or create a tracked issue for it.",
        "source": "JavaScript Best Practices",
    },
    {
        "id": "JS-EVAL",
        "pattern": r"\beval\s*\(",
        "category": "anti_pattern",
        "severity": "critical",
        "description": "`eval()` is dangerous — allows arbitrary code execution.",
        "suggestion": "Use `JSON.parse()`, `Function()` constructor, or restructure the logic.",
        "source": "JavaScript Security Best Practices",
    },
    {
        "id": "JS-DOCUMENT-WRITE",
        "pattern": r"document\.write\s*\(",
        "category": "anti_pattern",
        "severity": "high",
        "description": "`document.write()` can overwrite the entire page and is a security risk.",
        "suggestion": "Use DOM manipulation methods (`createElement`, `appendChild`) instead.",
        "source": "JavaScript Best Practices",
    },
]

REACT_RULES: list[dict] = [
    {
        "id": "REACT-INLINE-STYLE",
        "pattern": r"style=\{\{[^}]{60,}\}\}",
        "category": "style",
        "severity": "low",
        "description": "Large inline style object detected. Inline styles reduce maintainability.",
        "suggestion": "Extract styles to a CSS module, styled-component, or constant object.",
        "source": "React Best Practices / freeCodeCamp",
    },
    {
        "id": "REACT-INDEX-KEY",
        "pattern": r"\.map\s*\([^)]*,\s*(\w+)\s*\)\s*=>\s*[^}]*key\s*=\s*\{?\s*\1\s*\}?",
        "category": "anti_pattern",
        "severity": "medium",
        "description": "Array index used as `key` prop. This causes rendering issues when items change order.",
        "suggestion": "Use a unique identifier (e.g., `item.id`) as the key prop.",
        "source": "React Best Practices / freeCodeCamp",
    },
    {
        "id": "REACT-DANGEROUS-HTML",
        "pattern": r"dangerouslySetInnerHTML",
        "category": "anti_pattern",
        "severity": "high",
        "description": "`dangerouslySetInnerHTML` opens up XSS attack vectors.",
        "suggestion": "Sanitize HTML with DOMPurify before setting inner HTML.",
        "source": "React Best Practices / Security / freeCodeCamp",
    },
    {
        "id": "REACT-DIRECT-MUTATE",
        "pattern": r"(?:this\.)?state\.\w+\s*=\s*(?!this\.setState|useState)",
        "category": "anti_pattern",
        "severity": "high",
        "description": "Direct state mutation detected. React state must be updated immutably.",
        "suggestion": "Use `setState()` or the setter from `useState()` hook.",
        "source": "React Best Practices / React Docs",
    },
    {
        "id": "REACT-MISSING-DEP",
        "pattern": r"useEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*\b(props|state)\b[^}]*\}\s*,\s*\[\s*\]\s*\)",
        "category": "anti_pattern",
        "severity": "medium",
        "description": "`useEffect` with empty dependency array references `props` or `state` — may cause stale closures.",
        "suggestion": "Add the referenced values to the dependency array or use `useCallback`.",
        "source": "React Hooks Best Practices",
    },
    {
        "id": "REACT-MANY-USESTATE",
        "pattern": None,  # Custom check — count useState calls
        "category": "complexity",
        "severity": "medium",
        "description": "Component has {count} `useState` hooks — consider `useReducer` for complex state.",
        "suggestion": "When a component exceeds 4 useState hooks, refactor to `useReducer` or split into sub-components.",
        "source": "React Best Practices / freeCodeCamp",
    },
    {
        "id": "REACT-PROP-DRILLING",
        "pattern": None,  # Custom check — look for props passed through many levels
        "category": "design_pattern",
        "severity": "medium",
        "description": "Potential prop drilling: `{prop}` is passed through multiple component layers.",
        "suggestion": "Use React Context, a state management library, or component composition.",
        "source": "React Best Practices / freeCodeCamp",
    },
]

TYPESCRIPT_RULES: list[dict] = [
    {
        "id": "TS-ANY-TYPE",
        "pattern": r":\s*any\b",
        "category": "type_safety",
        "severity": "medium",
        "description": "Type `any` bypasses TypeScript's type system entirely.",
        "suggestion": "Use a specific type, `unknown`, or a generic instead of `any`.",
        "source": "TypeScript Best Practices / Do's and Don'ts",
    },
    {
        "id": "TS-NON-NULL-ASSERT",
        "pattern": r"\w+!\.",
        "category": "type_safety",
        "severity": "low",
        "description": "Non-null assertion `!.` suppresses null checks — can cause runtime errors.",
        "suggestion": "Use optional chaining `?.` with a proper null check instead.",
        "source": "TypeScript Best Practices",
    },
    {
        "id": "TS-ENUM-CONST",
        "pattern": r"^\s*enum\s+\w+",
        "category": "style",
        "severity": "low",
        "description": "Regular `enum` generates extra JavaScript at runtime.",
        "suggestion": "Use `const enum` or a union type for zero-runtime-cost alternatives.",
        "source": "TypeScript Best Practices",
    },
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _to_snake_case(name: str) -> str:
    """Convert PascalCase or camelCase to snake_case."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _get_rules_for_file(file_path: str) -> list[dict]:
    """Return applicable rules based on file extension."""
    ext = Path(file_path).suffix.lower()
    rules: list[dict] = []

    if ext == ".py":
        rules.extend(PYTHON_RULES)
    elif ext in {".js", ".jsx"}:
        rules.extend(JS_TS_RULES)
        if ext == ".jsx":
            rules.extend(REACT_RULES)
    elif ext in {".ts", ".tsx"}:
        rules.extend(JS_TS_RULES)
        rules.extend(TYPESCRIPT_RULES)
        if ext == ".tsx":
            rules.extend(REACT_RULES)

    return rules


def _check_react_usestate_count(source: str, file_path: str) -> list[dict]:
    """Check for excessive useState hooks in React components."""
    findings: list[dict] = []

    # Split into component blocks (rough heuristic — function/const components)
    component_pattern = re.compile(
        r"(?:export\s+)?(?:default\s+)?(?:function|const)\s+([A-Z]\w+)",
        re.MULTILINE,
    )
    for match in component_pattern.finditer(source):
        name = match.group(1)
        start = match.start()
        # Find the component body (next ~500 lines)
        body_end = min(start + 15000, len(source))
        body = source[start:body_end]

        # Count useState calls
        use_state_count = len(re.findall(r"\buseState\s*[<(]", body[:5000]))
        if use_state_count > 4:
            line_num = source[:start].count("\n") + 1
            findings.append({
                "file": file_path,
                "line_start": line_num,
                "line_end": line_num,
                "category": "complexity",
                "severity": "medium",
                "description": f"Component `{name}` has {use_state_count} `useState` hooks — consider `useReducer` for complex state.",
                "suggestion": "When a component exceeds 4 useState hooks, refactor to `useReducer` or split into sub-components.",
                "source": "React Best Practices / freeCodeCamp",
                "rule_id": "REACT-MANY-USESTATE",
            })

    return findings


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

class StandardsCheckerInput(BaseModel):
    """Input schema for the coding standards checker tool."""

    file_path: str = Field(
        ...,
        description="Absolute path to the source file to check.",
    )
    relative_path: str = Field(
        ...,
        description="Relative path of the file within the repo (used in findings).",
    )


@tool(args_schema=StandardsCheckerInput)
def check_coding_standards(file_path: str, relative_path: str) -> str:
    """Check a source file against language-specific coding standards and best practices.

    Applies deterministic regex-based rules derived from community best practices
    (PEP 8, JavaScript Clean Code, React patterns, TypeScript do's and don'ts)
    to detect naming violations, anti-patterns, style issues, and more.

    Args:
        file_path: Absolute path to the file to analyze.
        relative_path: Repo-relative path for reporting.

    Returns:
        JSON string with a list of coding standard violations found.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.exists():
        return json.dumps({"error": f"File not found: {file_path}", "findings": []})

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return json.dumps({"error": str(e), "findings": []})

    lines = source.split("\n")
    rules = _get_rules_for_file(relative_path)
    findings: list[dict] = []

    for rule in rules:
        if rule.get("pattern") is None:
            continue  # Custom checks handled separately

        try:
            pattern = re.compile(rule["pattern"], re.MULTILINE)
        except re.error:
            continue

        for match in pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1

            # Skip comment-only lines
            stripped = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Build description with match context
            extract = match.group(rule.get("extract_group", 0)) if rule.get("extract_group") else ""
            desc = rule["description"]
            suggestion = rule["suggestion"]

            if "{match}" in desc:
                desc = desc.replace("{match}", extract)
            if "{fix}" in suggestion and rule.get("fix_fn") == "to_snake_case":
                suggestion = suggestion.replace("{fix}", _to_snake_case(extract))
            if "{tag}" in desc:
                tag = match.group(1) if match.lastindex and match.lastindex >= 1 else "TODO"
                desc = desc.replace("{tag}", tag)
                suggestion = suggestion.replace("{tag}", tag)
            if "{method}" in desc:
                method = match.group(1) if match.lastindex and match.lastindex >= 1 else "log"
                desc = desc.replace("{method}", method)
            if "{value}" in suggestion:
                val = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                suggestion = suggestion.replace("{value}", val)

            findings.append({
                "file": relative_path,
                "line_start": line_num,
                "line_end": line_num,
                "category": rule["category"],
                "severity": rule["severity"],
                "description": desc,
                "suggestion": suggestion,
                "rule_id": rule["id"],
                "source": rule.get("source", ""),
            })

    # Run custom React checks
    ext = Path(relative_path).suffix.lower()
    if ext in {".jsx", ".tsx"}:
        findings.extend(_check_react_usestate_count(source, relative_path))

    return json.dumps({
        "status": "success",
        "file": relative_path,
        "total_violations": len(findings),
        "findings": findings,
    }, indent=2)
