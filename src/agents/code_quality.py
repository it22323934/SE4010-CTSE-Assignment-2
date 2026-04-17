"""Code Quality analysis agent for CodeSentinel.

Analyzes pre-processed AST data and code metrics to identify code smells,
anti-patterns, and structural issues. Uses deepseek-coder-v2:16b for
purpose-built code understanding and structural analysis.
"""

import json
import uuid
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import LLM_SETTINGS, MAX_CLASS_LINES, MAX_CLASS_METHODS, MAX_CYCLOMATIC_COMPLEXITY, MAX_FUNCTION_LENGTH, MAX_NESTING_DEPTH, MODELS, OLLAMA_BASE_URL
from src.observability.tracer import get_tracer
from src.state import AuditState
from src.tools.ast_parser import parse_ast_tool

SYSTEM_PROMPT = """You are the Code Quality Analyst in CodeSentinel, an automated code audit system.

## YOUR ROLE
You analyze pre-processed AST (Abstract Syntax Tree) data and code metrics to identify code smells, anti-patterns, and structural issues in a codebase.

## CRITICAL CONSTRAINTS
- You NEVER invent or fabricate file paths, function names, or line numbers.
- You ONLY reference data provided to you in the input.
- You respond ONLY in the JSON format specified below. No prose. No markdown. Just JSON.
- If data is missing or incomplete, skip that file — do not guess.

## WHAT YOU DETECT
1. Long functions (>50 lines) — suggest decomposition
2. Deep nesting (>3 levels) — suggest early returns or extraction
3. God classes (>10 methods OR >300 lines) — suggest splitting by responsibility
4. High cyclomatic complexity (>10) — suggest simplification
5. Dead code (unused imports, unreachable branches) — suggest removal
6. Overly broad exception handling (bare except:) — suggest specific exceptions

## OUTPUT FORMAT
Respond with a JSON array of findings:
[
    {
        "file": "src/utils.py",
        "line_start": 45,
        "line_end": 120,
        "category": "long_function",
        "severity": "high",
        "description": "Function `process_data` is 75 lines with 3 distinct responsibilities.",
        "suggestion": "Extract validation logic into `validate_data()` and storage into `persist_data()`.",
        "confidence": 0.85
    }
]

## SEVERITY LEVELS
- critical: Blocks maintainability or causes bugs
- high: Significant technical debt (long functions, deep nesting)
- medium: Code smell (missing types, broad exceptions)
- low: Style issue or minor improvement

## WHAT YOU MUST NOT DO
- Do NOT analyze security vulnerabilities
- Do NOT suggest refactored code snippets
- Do NOT produce prose explanations — JSON array only
"""


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
            # Only analyze Python files for now
            if not file_rel.endswith(".py"):
                continue

            file_path = str(Path(repo_path) / file_rel)

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
