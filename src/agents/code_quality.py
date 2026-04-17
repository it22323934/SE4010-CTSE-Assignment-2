"""Code Quality analysis agent for CodeSentinel.

Analyzes pre-processed AST data and code metrics to identify code smells,
anti-patterns, and structural issues. Uses deepseek-coder-v2:16b for
purpose-built code understanding and structural analysis.

Supports Python (via AST) and JavaScript/TypeScript (via regex-based analysis).
"""

import json
import re
import uuid
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import LLM_SETTINGS, MAX_CLASS_LINES, MAX_CLASS_METHODS, MAX_CYCLOMATIC_COMPLEXITY, MAX_FUNCTION_LENGTH, MAX_NESTING_DEPTH, MODELS, OLLAMA_BASE_URL
from src.observability.tracer import get_tracer
from src.state import AuditState
from src.tools.ast_parser import parse_ast_tool
from src.tools.standards_checker import check_coding_standards
from src.tools.duplication_detector import detect_code_duplication
from src.tools.structure_analyzer import analyze_project_structure

# File extensions supported for code quality analysis
PYTHON_EXTENSIONS = {".py"}
JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
SUPPORTED_EXTENSIONS = PYTHON_EXTENSIONS | JS_TS_EXTENSIONS

SYSTEM_PROMPT = """You are the Code Quality Analyst in CodeSentinel, an automated multi-agent code audit system.

## YOUR ROLE
You analyze pre-processed AST (Abstract Syntax Tree) data and code metrics to identify code smells,
anti-patterns, and structural issues that degrade maintainability, readability, and reliability.
You are an expert in software engineering best practices, SOLID principles, and clean code patterns.

## CRITICAL CONSTRAINTS
- You NEVER invent or fabricate file paths, function names, or line numbers.
- You ONLY reference data provided to you in the input — every finding must trace to actual AST data.
- You respond ONLY in the JSON format specified below. No prose. No markdown. Just JSON.
- If data is missing or incomplete, skip that file — do not guess or extrapolate.
- You do NOT analyze security vulnerabilities — the Security Agent handles that.

## WHAT YOU DETECT
1. **Long Functions** (>50 lines) — suggest decomposition into focused, testable units
2. **Deep Nesting** (>3 levels) — suggest early returns, guard clauses, or extraction
3. **God Classes** (>10 methods OR >300 lines) — suggest Single Responsibility splitting
4. **High Cyclomatic Complexity** (>10) — suggest simplification via polymorphism or strategy pattern
5. **Dead Code** (unused imports, unreachable branches) — suggest removal with explanation
6. **Bare Exception Handling** (bare `except:`) — suggest specific exception types
7. **Code Duplication** — identify repeated patterns that should be abstracted
8. **Excessive Parameters** (>5 params) — suggest parameter objects or builder pattern
9. **Tight Coupling** — flag classes with too many external dependencies

## ANALYSIS APPROACH
- First, examine the deterministic findings from AST analysis (these are high-confidence).
- Then, look for patterns that require deeper reasoning:
  - Are there functions doing multiple unrelated things? (SRP violation)
  - Are there deeply nested conditionals that obscure logic?
  - Are there repeated code patterns across multiple functions?
- Assign confidence scores honestly: 0.95 for clear violations, 0.70-0.85 for judgment calls.

## OUTPUT FORMAT
Respond with a JSON array of findings:
[
    {
        "file": "src/utils.py",
        "line_start": 45,
        "line_end": 120,
        "category": "long_function",
        "severity": "high",
        "description": "Function `process_data` is 75 lines with 3 distinct responsibilities: validation, transformation, and persistence.",
        "suggestion": "Extract validation logic into `validate_data()`, transformation into `transform_data()`, and storage into `persist_data()`.",
        "confidence": 0.85
    }
]

## SEVERITY LEVELS
- **critical**: Blocks maintainability, causes bugs, or makes testing impossible
- **high**: Significant technical debt (long functions >100 lines, deep nesting >5, complexity >15)
- **medium**: Code smell that should be addressed (bare exceptions, missing types, moderate complexity)
- **low**: Style issue or minor improvement opportunity

## WHAT YOU MUST NOT DO
- Do NOT analyze security vulnerabilities — the Security Agent handles that
- Do NOT suggest refactored code snippets — the Refactoring Agent handles that
- Do NOT produce prose explanations — JSON array only
- Do NOT flag issues in test files unless they are egregious
- Do NOT lower confidence to avoid flagging real issues
"""


def _analyze_js_ts_file(file_path: str, abs_path: str) -> list[dict]:
    """Perform regex-based code quality analysis on JavaScript/TypeScript files.

    Since the AST parser only supports Python, this uses regex patterns
    to detect functions, classes, nesting depth, and common code smells
    in JS/TS source files.

    Args:
        file_path: Relative file path for reporting.
        abs_path: Absolute path to the file on disk.

    Returns:
        List of finding dicts for detected issues.
    """
    findings: list[dict] = []

    try:
        source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = source.split("\n")
    total_lines = len(lines)

    # --- Detect functions and their line counts ---
    # Matches: function name(...), const name = (...) =>, export function name(...)
    func_pattern = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|"
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|"
        r"(\w+)\s*\([^)]*\)\s*\{)",
        re.MULTILINE,
    )

    # Track brace depth to estimate function boundaries
    func_regions: list[dict] = []
    for match in func_pattern.finditer(source):
        name = match.group(1) or match.group(2) or match.group(3)
        if not name or name in ("if", "for", "while", "switch", "catch", "else"):
            continue
        start_line = source[:match.start()].count("\n") + 1

        # Find function end by counting braces
        brace_depth = 0
        found_open = False
        end_line = start_line
        for i in range(start_line - 1, min(start_line + 500, total_lines)):
            line = lines[i]
            for ch in line:
                if ch == "{":
                    brace_depth += 1
                    found_open = True
                elif ch == "}":
                    brace_depth -= 1
                    if found_open and brace_depth <= 0:
                        end_line = i + 1
                        break
            if found_open and brace_depth <= 0:
                break
        else:
            end_line = min(start_line + 50, total_lines)

        line_count = end_line - start_line + 1
        func_regions.append({
            "name": name,
            "line_start": start_line,
            "line_end": end_line,
            "line_count": line_count,
        })

    # Check for long functions
    for func in func_regions:
        if func["line_count"] > MAX_FUNCTION_LENGTH:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "category": "long_function",
                "agent_source": "code_quality",
                "severity": "high",
                "cwe_id": None,
                "description": f"Function `{func['name']}` is {func['line_count']} lines long (threshold: {MAX_FUNCTION_LENGTH}).",
                "suggestion": f"Decompose `{func['name']}` into smaller, focused functions with single responsibilities.",
                "confidence": 0.85,
                "is_new": None,
            })

    # --- Detect deep nesting ---
    for func in func_regions:
        max_depth = 0
        for i in range(func["line_start"] - 1, min(func["line_end"], total_lines)):
            line = lines[i]
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            # Estimate nesting: assume 2-space or 4-space indent
            indent_unit = 2 if "  " in source[:200] and "    " not in source[:200] else 4
            depth = indent // indent_unit
            max_depth = max(max_depth, depth)

        if max_depth > MAX_NESTING_DEPTH + 1:  # JS tends to have higher base nesting
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "category": "deep_nesting",
                "agent_source": "code_quality",
                "severity": "medium",
                "cwe_id": None,
                "description": f"Function `{func['name']}` has approximately {max_depth} levels of nesting.",
                "suggestion": "Use early returns, guard clauses, or extract nested logic into helper functions.",
                "confidence": 0.75,
                "is_new": None,
            })

    # --- Detect large classes/components ---
    class_pattern = re.compile(
        r"^\s*(?:export\s+)?class\s+(\w+)",
        re.MULTILINE,
    )
    for match in class_pattern.finditer(source):
        name = match.group(1)
        start_line = source[:match.start()].count("\n") + 1
        brace_depth = 0
        found_open = False
        end_line = start_line
        for i in range(start_line - 1, min(start_line + 1000, total_lines)):
            for ch in lines[i]:
                if ch == "{":
                    brace_depth += 1
                    found_open = True
                elif ch == "}":
                    brace_depth -= 1
                    if found_open and brace_depth <= 0:
                        end_line = i + 1
                        break
            if found_open and brace_depth <= 0:
                break

        class_lines = end_line - start_line + 1
        # Count methods in class body
        class_body = "\n".join(lines[start_line - 1:end_line])
        method_count = len(re.findall(r"(?:async\s+)?\w+\s*\([^)]*\)\s*\{", class_body))

        if method_count > MAX_CLASS_METHODS or class_lines > MAX_CLASS_LINES:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": start_line,
                "line_end": end_line,
                "category": "god_class",
                "agent_source": "code_quality",
                "severity": "high",
                "cwe_id": None,
                "description": f"Class `{name}` has ~{method_count} methods and {class_lines} lines.",
                "suggestion": f"Split `{name}` into smaller classes with single responsibilities.",
                "confidence": 0.80,
                "is_new": None,
            })

    # --- Detect excessive parameters ---
    param_pattern = re.compile(
        r"(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?)\s*\(([^)]{40,})\)",
    )
    for match in param_pattern.finditer(source):
        params = [p.strip() for p in match.group(1).split(",") if p.strip()]
        if len(params) > 5:
            line_num = source[:match.start()].count("\n") + 1
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": line_num,
                "line_end": line_num,
                "category": "excessive_parameters",
                "agent_source": "code_quality",
                "severity": "medium",
                "cwe_id": None,
                "description": f"Function has {len(params)} parameters (threshold: 5).",
                "suggestion": "Consider using an options/config object parameter instead of many individual parameters.",
                "confidence": 0.85,
                "is_new": None,
            })

    # --- Detect console.log left in production code ---
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("console.log(") and not stripped.startswith("//"):
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": i + 1,
                "line_end": i + 1,
                "category": "debug_code",
                "agent_source": "code_quality",
                "severity": "low",
                "cwe_id": None,
                "description": "console.log() call left in production code.",
                "suggestion": "Remove debug logging or replace with a proper logging framework.",
                "confidence": 0.90,
                "is_new": None,
            })

    # --- Detect TODO/FIXME/HACK comments ---
    todo_pattern = re.compile(r"(?://|/\*|\*)\s*(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)
    for i, line in enumerate(lines):
        match = todo_pattern.search(line)
        if match:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": i + 1,
                "line_end": i + 1,
                "category": "todo_comment",
                "agent_source": "code_quality",
                "severity": "low",
                "cwe_id": None,
                "description": f"{match.group(1).upper()} comment indicates unfinished or problematic code.",
                "suggestion": "Address the TODO/FIXME or create a tracked issue for it.",
                "confidence": 0.95,
                "is_new": None,
            })

    # --- File-level metrics ---
    if total_lines > 500:
        findings.append({
            "id": f"CQ-{uuid.uuid4().hex[:6]}",
            "file": file_path,
            "line_start": 1,
            "line_end": total_lines,
            "category": "large_file",
            "agent_source": "code_quality",
            "severity": "medium",
            "cwe_id": None,
            "description": f"File is {total_lines} lines long, which may indicate it has too many responsibilities.",
            "suggestion": "Consider splitting into multiple modules organized by feature or responsibility.",
            "confidence": 0.80,
            "is_new": None,
        })

    return findings


def _analyze_file_locally(file_path: str, ast_data: dict) -> list[dict]:
    """Perform deterministic code quality checks on parsed AST data.

    This runs BEFORE the LLM to catch obvious issues with high confidence.
    The LLM then provides deeper analysis on the same data.

    Args:
        file_path: Path to the analyzed file.
        ast_data: Parsed AST data from parse_ast_tool.

    Returns:
        List of finding dicts for deterministic detections.
    """
    findings: list[dict] = []
    data = ast_data.get("data", {})

    # Check functions
    for func in data.get("functions", []):
        # Long function check
        line_count = func.get("line_count", 0)
        if line_count > MAX_FUNCTION_LENGTH:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "category": "long_function",
                "agent_source": "code_quality",
                "severity": "high",
                "cwe_id": None,
                "description": f"Function `{func['name']}` is {line_count} lines long (threshold: {MAX_FUNCTION_LENGTH}).",
                "suggestion": f"Consider decomposing `{func['name']}` into smaller, focused functions.",
                "confidence": 0.95,
                "is_new": None,
            })

        # Deep nesting check
        nesting = func.get("max_nesting_depth", 0)
        if nesting > MAX_NESTING_DEPTH:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "category": "deep_nesting",
                "agent_source": "code_quality",
                "severity": "medium",
                "cwe_id": None,
                "description": f"Function `{func['name']}` has {nesting} levels of nesting (threshold: {MAX_NESTING_DEPTH}).",
                "suggestion": "Use early returns and extract inner loops to helper functions.",
                "confidence": 0.90,
                "is_new": None,
            })

        # High complexity check
        complexity = func.get("cyclomatic_complexity", 0)
        if complexity > MAX_CYCLOMATIC_COMPLEXITY:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "category": "high_complexity",
                "agent_source": "code_quality",
                "severity": "high",
                "cwe_id": None,
                "description": f"Function `{func['name']}` has cyclomatic complexity of {complexity} (threshold: {MAX_CYCLOMATIC_COMPLEXITY}).",
                "suggestion": "Simplify control flow, extract conditional branches into separate functions.",
                "confidence": 0.92,
                "is_new": None,
            })

    # Check classes
    for cls in data.get("classes", []):
        methods = cls.get("methods_count", 0)
        total_lines = cls.get("total_lines", 0)

        if methods > MAX_CLASS_METHODS or total_lines > MAX_CLASS_LINES:
            findings.append({
                "id": f"CQ-{uuid.uuid4().hex[:6]}",
                "file": file_path,
                "line_start": cls["line_start"],
                "line_end": cls["line_end"],
                "category": "god_class",
                "agent_source": "code_quality",
                "severity": "high",
                "cwe_id": None,
                "description": f"Class `{cls['name']}` has {methods} methods and {total_lines} lines.",
                "suggestion": f"Split `{cls['name']}` into smaller classes with single responsibilities.",
                "confidence": 0.88,
                "is_new": None,
            })

    # Check bare excepts
    for be in data.get("bare_excepts", []):
        findings.append({
            "id": f"CQ-{uuid.uuid4().hex[:6]}",
            "file": file_path,
            "line_start": be["line"],
            "line_end": be.get("end_line", be["line"]),
            "category": "bare_except",
            "agent_source": "code_quality",
            "severity": "medium",
            "cwe_id": None,
            "description": "Bare `except:` clause catches all exceptions silently, including KeyboardInterrupt.",
            "suggestion": "Catch specific exceptions: `except (ValueError, KeyError) as e:`",
            "confidence": 0.95,
            "is_new": None,
        })

    # Check unused imports
    for ui in data.get("unused_imports", []):
        findings.append({
            "id": f"CQ-{uuid.uuid4().hex[:6]}",
            "file": file_path,
            "line_start": ui["line"],
            "line_end": ui["line"],
            "category": "dead_import",
            "agent_source": "code_quality",
            "severity": "low",
            "cwe_id": None,
            "description": f"Import `{ui['name']}` appears to be unused.",
            "suggestion": "Remove unused import.",
            "confidence": 0.85,
            "is_new": None,
        })

    return findings


def code_quality_node(state: AuditState) -> dict:
    """Code Quality agent — analyze priority files for structural issues.

    Parses each priority file's AST, runs deterministic checks, then
    optionally feeds data to the LLM for deeper analysis.

    Args:
        state: Current global audit state with audit_plan.

    Returns:
        State update with code_quality_findings and agent_traces.
    """
    tracer = get_tracer()
    tracer.start_agent("code_quality", "Analyzing code quality for priority files")

    try:
        plan = state.get("audit_plan", {})
        priority_files = plan.get("priority_files", [])
        repo_path = state["repo_path"]

        all_findings: list[dict] = []

        for file_rel in priority_files:
            file_ext = Path(file_rel).suffix
            file_path = str(Path(repo_path) / file_rel)

            # Skip unsupported file types
            if file_ext not in SUPPORTED_EXTENSIONS:
                continue

            # JavaScript/TypeScript — regex-based analysis
            if file_ext in JS_TS_EXTENSIONS:
                js_findings = _analyze_js_ts_file(file_rel, file_path)
                all_findings.extend(js_findings)
                tracer.log_tool_call(
                    "code_quality",
                    "js_ts_analyzer",
                    {"file_path": file_rel},
                    f"Analyzed {file_rel}: {len(js_findings)} findings",
                )
                continue

            # Python — AST-based analysis

            # Call AST parser tool
            ast_result_raw = parse_ast_tool.invoke({
                "file_path": file_path,
                "include_complexity": True,
            })
            ast_result = json.loads(ast_result_raw)
            tracer.log_tool_call(
                "code_quality",
                "ast_parser",
                {"file_path": file_rel},
                f"Parsed {file_rel}: status={ast_result.get('status')}",
            )

            if ast_result.get("status") != "success":
                continue

            # Run deterministic analysis
            file_findings = _analyze_file_locally(file_rel, ast_result)
            all_findings.extend(file_findings)

        # --- Coding Standards Check (per file) ---
        for file_rel in priority_files:
            file_ext = Path(file_rel).suffix
            if file_ext not in SUPPORTED_EXTENSIONS:
                continue
            try:
                abs_file = str(Path(repo_path) / file_rel)
                standards_raw = check_coding_standards.invoke({
                    "file_path": abs_file,
                    "relative_path": file_rel,
                })
                standards_result = json.loads(standards_raw)
                violations = standards_result.get("violations", [])
                for v in violations:
                    all_findings.append({
                        "id": f"CQ-{uuid.uuid4().hex[:6]}",
                        "file": file_rel,
                        "line_start": v.get("line", 0),
                        "line_end": v.get("line", 0),
                        "category": v.get("category", "coding_standard"),
                        "agent_source": "code_quality",
                        "severity": v.get("severity", "low"),
                        "cwe_id": None,
                        "description": v.get("description", ""),
                        "suggestion": v.get("suggestion", ""),
                        "confidence": 0.90,
                        "is_new": None,
                    })
                tracer.log_tool_call(
                    "code_quality",
                    "standards_checker",
                    {"file_path": file_rel},
                    f"Standards check on {file_rel}: {len(violations)} violations",
                )
            except Exception as std_err:
                tracer.log_error("code_quality", f"Standards check failed for {file_rel}: {std_err}")

        # --- Code Duplication Detection (whole repo) ---
        try:
            target_files_for_dup = [
                f for f in priority_files if Path(f).suffix in SUPPORTED_EXTENSIONS
            ]
            dup_raw = detect_code_duplication.invoke({
                "repo_path": repo_path,
                "target_files": target_files_for_dup,
            })
            dup_result = json.loads(dup_raw)
            dup_findings = dup_result.get("findings", [])
            for df in dup_findings:
                first_loc = df.get("locations", [{}])[0]
                all_findings.append({
                    "id": f"CQ-{uuid.uuid4().hex[:6]}",
                    "file": first_loc.get("file", ""),
                    "line_start": first_loc.get("line_start", 0),
                    "line_end": first_loc.get("line_end", 0),
                    "category": "code_duplication",
                    "agent_source": "code_quality",
                    "severity": df.get("severity", "medium"),
                    "cwe_id": None,
                    "description": df.get("description", ""),
                    "suggestion": df.get("suggestion", ""),
                    "confidence": 0.85,
                    "is_new": None,
                })
            tracer.log_tool_call(
                "code_quality",
                "duplication_detector",
                {"repo_path": repo_path, "files": len(target_files_for_dup)},
                f"Duplication scan: {dup_result.get('duplicate_groups', 0)} groups in {dup_result.get('files_scanned', 0)} files",
            )
        except Exception as dup_err:
            tracer.log_error("code_quality", f"Duplication detection failed: {dup_err}")

        # --- Project Structure & Design Pattern Analysis (whole repo) ---
        try:
            struct_raw = analyze_project_structure.invoke({
                "repo_path": repo_path,
                "priority_files": priority_files,
            })
            struct_result = json.loads(struct_raw)
            struct_findings = struct_result.get("findings", [])
            for sf in struct_findings:
                all_findings.append({
                    "id": f"CQ-{uuid.uuid4().hex[:6]}",
                    "file": sf.get("file", ""),
                    "line_start": 0,
                    "line_end": 0,
                    "category": sf.get("category", "project_structure"),
                    "agent_source": "code_quality",
                    "severity": sf.get("severity", "medium"),
                    "cwe_id": None,
                    "description": sf.get("description", ""),
                    "suggestion": sf.get("suggestion", ""),
                    "confidence": 0.80,
                    "is_new": None,
                })
            tracer.log_tool_call(
                "code_quality",
                "structure_analyzer",
                {"repo_path": repo_path},
                f"Structure analysis: {len(struct_findings)} findings, frameworks={struct_result.get('detected_frameworks', [])}",
            )
        except Exception as struct_err:
            tracer.log_error("code_quality", f"Structure analysis failed: {struct_err}")

        # Optionally enhance with LLM analysis
        if all_findings and priority_files:
            try:
                model = ChatOllama(
                    model=MODELS["code_quality"],
                    base_url=OLLAMA_BASE_URL,
                    temperature=LLM_SETTINGS["code_quality"]["temperature"],
                    num_predict=LLM_SETTINGS["code_quality"]["num_predict"],
                )

                analysis_summary = json.dumps([
                    {
                        "file": f.get("file"),
                        "category": f.get("category"),
                        "description": f.get("description"),
                    }
                    for f in all_findings[:10]  # Limit context for SLM
                ], indent=2)

                messages = [
                    SystemMessage(content=SYSTEM_PROMPT),
                    HumanMessage(content=f"Review these findings and confirm or adjust severity levels. Return the same JSON array format:\n{analysis_summary}"),
                ]

                response = model.invoke(messages)
                tracer.log_llm_call("code_quality", MODELS["code_quality"], "Review findings", f"Response: {len(response.content)} chars")

            except Exception as llm_err:
                tracer.log_error("code_quality", f"LLM enhancement failed (non-critical): {llm_err}")

        trace = tracer.end_agent("code_quality", f"Found {len(all_findings)} code quality issues")

        return {
            "code_quality_findings": all_findings,
            "agent_traces": [trace],
        }

    except Exception as e:
        trace = tracer.end_agent("code_quality", "", error=str(e))
        return {
            "code_quality_findings": [],
            "agent_traces": [trace],
            "errors": [{"agent": "code_quality", "error": str(e)}],
        }
