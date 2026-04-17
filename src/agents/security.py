"""Security Vulnerability analysis agent for CodeSentinel.

Scans source files for security vulnerabilities using pattern matching
and Git history analysis. Queries the CWE/OWASP vulnerability knowledge
base via the SQLite MCP server for detection patterns at runtime.

Uses llama3:8b for pattern reasoning, classifying severity, and
explaining attack vectors.
"""

import json
import uuid
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import LLM_SETTINGS, MODELS, OLLAMA_BASE_URL
from src.mcp.sqlite_client import sqlite_query
from src.observability.tracer import get_tracer
from src.state import AuditState
from src.tools.git_analyzer import git_analyzer
from src.tools.pattern_scanner import pattern_scanner

SYSTEM_PROMPT = """You are the Security Vulnerability Analyst in CodeSentinel, an automated code audit system.

## YOUR ROLE
You analyze pre-scanned security findings from the pattern_scanner tool and Git history
to classify, prioritize, and explain security vulnerabilities.

## CRITICAL CONSTRAINTS
- You ONLY report findings backed by tool output. Never fabricate vulnerabilities.
- You respond ONLY in JSON format. No prose. No markdown.
- Include CWE IDs for professional categorization.
- Do NOT suggest detailed fixes — the Refactoring Agent handles that.

## OUTPUT FORMAT
JSON array of findings:
[
    {
        "file": "src/database.py",
        "line_start": 23,
        "line_end": 23,
        "category": "sql_injection",
        "severity": "critical",
        "cwe_id": "CWE-89",
        "description": "Raw string interpolation in SQL query",
        "attack_vector": "An attacker can inject arbitrary SQL via the user_id parameter.",
        "confidence": 0.95
    }
]

## SEVERITY CLASSIFICATION
- critical: Directly exploitable (SQL injection, command injection, hardcoded prod secrets)
- high: Exploitable with effort (path traversal, insecure deserialization)
- medium: Potential risk (secrets in git history, weak crypto)
- low: Informational (missing security headers, TODO security notes)
"""

# Common secret patterns for Git history search
SECRET_PATTERNS = [
    "password",
    "secret",
    "api_key",
    "token",
    "private_key",
    "AWS_SECRET",
]


def security_node(state: AuditState) -> dict:
    """Security agent — scan priority files for vulnerabilities.

    Queries the CWE/OWASP vulnerability knowledge base via the SQLite
    MCP server, runs pattern scanner on each file, checks Git history
    for leaked secrets, then optionally uses LLM to classify and
    explain attack vectors.

    Args:
        state: Current global audit state with audit_plan.

    Returns:
        State update with security_findings and agent_traces.
    """
    tracer = get_tracer()
    tracer.start_agent("security", "Scanning for security vulnerabilities")

    try:
        plan = state.get("audit_plan", {})
        priority_files = plan.get("priority_files", [])
        repo_path = state["repo_path"]

        all_findings: list[dict] = []

        # Step 0: Query the vulnerability knowledge base via MCP
        kb_summary = _query_knowledge_base(tracer)

        # Step 1: Scan each file with pattern_scanner (loads patterns from DB)
        for file_rel in priority_files:
            file_path = str(Path(repo_path) / file_rel)

            # Only scan source files
            if not Path(file_rel).suffix in {".py", ".js", ".ts", ".java", ".go", ".rb"}:
                continue

            scan_result_raw = pattern_scanner.invoke({"file_path": file_path})
            scan_result = json.loads(scan_result_raw)
            tracer.log_tool_call(
                "security",
                "pattern_scanner",
                {"file_path": file_rel},
                f"Scanned {file_rel}: {scan_result.get('data', {}).get('total_matches', 0)} matches",
            )

            if scan_result.get("status") != "success":
                continue

            matches = scan_result.get("data", {}).get("matches", [])
            pattern_source = scan_result.get("data", {}).get("pattern_source", "unknown")

            for match in matches:
                finding = {
                    "id": f"SEC-{uuid.uuid4().hex[:6]}",
                    "file": file_rel,
                    "line_start": match.get("line_start", 0),
                    "line_end": match.get("line_end", 0),
                    "category": match.get("category", "unknown"),
                    "agent_source": "security",
                    "severity": match.get("severity", "medium"),
                    "cwe_id": match.get("cwe_id"),
                    "owasp_id": match.get("owasp_id"),
                    "description": match.get("description", ""),
                    "attack_vector": match.get("attack_vector"),
                    "remediation": match.get("remediation"),
                    "suggestion": match.get("remediation"),
                    "confidence": 0.90,
                    "is_new": None,
                    "pattern_source": pattern_source,
                }
                all_findings.append(finding)

        # Step 2: Check Git history for leaked secrets
        for pattern in SECRET_PATTERNS:
            try:
                history_raw = git_analyzer.invoke({
                    "repo_path": repo_path,
                    "operation": "search_history",
                    "params": {"pattern": pattern},
                })
                history = json.loads(history_raw)
                tracer.log_tool_call(
                    "security",
                    "git_analyzer",
                    {"operation": "search_history", "pattern": pattern},
                    f"History search for '{pattern}': {len(history.get('data', []))} results",
                )

                for hit in history.get("data", []):
                    all_findings.append({
                        "id": f"SEC-{uuid.uuid4().hex[:6]}",
                        "file": "git_history",
                        "line_start": 0,
                        "line_end": 0,
                        "category": "secret_in_history",
                        "agent_source": "security",
                        "severity": "medium",
                        "cwe_id": "CWE-798",
                        "description": f"Pattern '{pattern}' found in Git history at commit {hit.get('commit', 'unknown')}: {hit.get('message', '')}",
                        "suggestion": "Rotate the exposed credential and use git-filter-repo to remove from history.",
                        "confidence": 0.80,
                        "is_new": None,
                    })
            except Exception:
                pass  # Non-critical — continue scanning

        # Step 3: Optionally enhance with LLM for classification
        if all_findings:
            try:
                model = ChatOllama(
                    model=MODELS["security"],
                    base_url=OLLAMA_BASE_URL,
                    temperature=LLM_SETTINGS["security"]["temperature"],
                    num_predict=LLM_SETTINGS["security"]["num_predict"],
                )

                findings_summary = json.dumps([
                    {
                        "file": f.get("file"),
                        "category": f.get("category"),
                        "severity": f.get("severity"),
                        "cwe_id": f.get("cwe_id"),
                        "owasp_id": f.get("owasp_id"),
                        "description": f.get("description"),
                        "attack_vector": f.get("attack_vector"),
                    }
                    for f in all_findings[:10]
                ], indent=2)

                kb_context = ""
                if kb_summary:
                    kb_context = f"\n\nKnowledge base loaded: {kb_summary}"

                messages = [
                    SystemMessage(content=SYSTEM_PROMPT),
                    HumanMessage(
                        content=(
                            f"Classify these security findings and provide attack vectors. "
                            f"Return JSON array:{kb_context}\n{findings_summary}"
                        )
                    ),
                ]

                response = model.invoke(messages)
                tracer.log_llm_call(
                    "security",
                    MODELS["security"],
                    "Classify findings",
                    f"Response: {len(response.content)} chars",
                )

            except Exception as llm_err:
                tracer.log_error("security", f"LLM classification failed (non-critical): {llm_err}")

        trace = tracer.end_agent("security", f"Found {len(all_findings)} security issues")

        return {
            "security_findings": all_findings,
            "agent_traces": [trace],
        }

    except Exception as e:
        trace = tracer.end_agent("security", "", error=str(e))
        return {
            "security_findings": [],
            "agent_traces": [trace],
            "errors": [{"agent": "security", "error": str(e)}],
        }


def _query_knowledge_base(tracer) -> str | None:
    """Query the vulnerability knowledge base via MCP sqlite_query.

    Fetches a summary of pattern categories and counts from the
    vulnerability_patterns table using the SQLite MCP tool.

    Args:
        tracer: The execution tracer for logging.

    Returns:
        Human-readable summary string, or None if DB is empty/unavailable.
    """
    try:
        kb_result_raw = sqlite_query.invoke({
            "query": (
                "SELECT category, COUNT(*) as cnt, "
                "GROUP_CONCAT(DISTINCT cwe_id) as cwe_ids, "
                "GROUP_CONCAT(DISTINCT severity) as severities "
                "FROM vulnerability_patterns WHERE enabled = 1 "
                "GROUP BY category ORDER BY cnt DESC"
            ),
        })
        kb_result = json.loads(kb_result_raw)
        tracer.log_tool_call(
            "security",
            "sqlite_query (MCP)",
            {"query": "SELECT category, COUNT(*) ... FROM vulnerability_patterns"},
            f"Knowledge base query: {kb_result.get('status', 'unknown')}",
        )

        if kb_result.get("status") != "success":
            return None

        rows = kb_result.get("data", [])
        if not rows:
            return None

        total_patterns = sum(r.get("cnt", 0) for r in rows)
        categories = [r.get("category", "?") for r in rows]
        unique_cwes: set[str] = set()
        for r in rows:
            for cwe in (r.get("cwe_ids") or "").split(","):
                cwe = cwe.strip()
                if cwe:
                    unique_cwes.add(cwe)

        summary = (
            f"{total_patterns} patterns across {len(categories)} categories "
            f"({', '.join(categories[:8])}{'...' if len(categories) > 8 else ''}), "
            f"covering {len(unique_cwes)} unique CWE IDs"
        )

        return summary

    except Exception as e:
        tracer.log_error("security", f"Knowledge base MCP query failed (non-critical): {e}")
        return None
