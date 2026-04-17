"""Orchestrator/Planner agent for CodeSentinel.

Responsible for:
1. Planning phase: Analyze repo structure, detect language/framework, prioritize files
2. Merge phase: Combine findings from Code Quality + Security agents, deduplicate
3. Final report: Compile everything into a structured report

Uses llama3:8b for strong general reasoning, planning, and delegation.
"""

import json
from datetime import datetime
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import LLM_SETTINGS, MODELS, OLLAMA_BASE_URL
from src.db.queries import (
    create_audit_run,
    get_previous_runs,
    insert_findings_batch,
    update_audit_run_counts,
    update_audit_run_status,
)
from src.observability.tracer import get_tracer
from src.state import AuditState
from src.tools.git_analyzer import git_analyzer
from src.tools.report_generator import generate_report

# --- System Prompts ---
PLANNING_SYSTEM_PROMPT = """You are the Orchestrator of CodeSentinel, an automated multi-agent code audit system.

## YOUR ROLE
You are the central planning intelligence. You receive a Git repository path and create a
comprehensive audit plan. You analyze the project structure, identify the primary programming
language and framework, enumerate source files to audit (prioritizing recently changed and
high-risk files), and configure specialist agent execution.

## ANALYSIS STRATEGY
1. **Language Detection**: Identify the dominant language by file extension distribution.
2. **Framework Detection**: Look for framework-specific files (e.g., requirements.txt, package.json, pom.xml, go.mod).
3. **File Prioritization**: Rank files by:
   - Recent change frequency (last 10 commits)
   - File type risk (auth, database, API endpoints, config files ranked higher)
   - File size (larger files are more likely to contain issues)
4. **Previous Audit Comparison**: If a prior audit exists, identify files changed since then.

## OUTPUT FORMAT
Respond with ONLY a JSON object (no markdown, no prose):
{
    "language": "python",
    "framework": "fastapi",
    "total_files": 42,
    "priority_files": ["src/auth.py", "src/models.py"],
    "prioritization_reason": "Files changed in last 10 commits, weighted by risk",
    "run_code_quality": true,
    "run_security": true,
    "previous_audit_exists": false,
    "previous_run_id": null,
    "notes": "FastAPI project with SQLAlchemy ORM. Auth module has frequent recent changes."
}

## CONSTRAINTS
- priority_files should be max 20 files. Focus on source code, not configs/tests/docs.
- Exclude __pycache__, node_modules, .git, build artifacts, and migration files.
- If previous audits exist, note what changed since the last run.
- Respond ONLY with valid JSON. No markdown fences. No explanation.

## WHAT YOU MUST NOT DO
- Do NOT analyze code yourself — delegate to specialist agents.
- Do NOT skip the security agent unless the repo contains only documentation.
- Do NOT include test files in priority_files unless specifically requested.
"""

MERGE_SYSTEM_PROMPT = """You are the Orchestrator merging findings from the Code Quality and Security agents.

## YOUR ROLE
You receive two lists of findings from specialist agents and must:
1. **Deduplicate**: Remove overlapping findings (same file + same line range + same category).
2. **Cross-Reference**: Identify findings that affect the same code region from different perspectives
   (e.g., a function flagged for both complexity AND security issues).
3. **Severity Escalation**: If a code region has both quality AND security findings, escalate
   the combined severity (e.g., a complex function with SQL injection becomes critical).
4. **Prioritize**: Order merged findings by severity (critical > high > medium > low),
   then by file path for consistent output.

## ESCALATION RULES
- Quality issue + Security issue in same function → escalate to at least "high"
- Multiple security issues in same file → escalate all to at least "high"
- Critical security + any quality issue → remains "critical" with cross-reference note

## OUTPUT FORMAT
Respond with ONLY a JSON object:
{
    "merged_findings": [...all deduplicated findings with updated severities...],
    "cross_references": [{"finding_ids": ["CQ-001", "SEC-003"], "reason": "same function has complexity and injection risk"}],
    "escalations": [{"finding_id": "CQ-001", "new_severity": "high", "reason": "co-located with security vulnerability"}],
    "summary": "10 unique findings: 3 critical, 2 high, 3 medium, 2 low"
}

## WHAT YOU MUST NOT DO
- Do NOT invent new findings — only merge what the agents reported.
- Do NOT reduce severity of any finding.
- Do NOT produce prose — JSON only.
"""


def orchestrator_node(state: AuditState) -> dict:
    """Orchestrator planning phase — analyze repo and build audit plan.

    Reads repo_path from state, calls git_analyzer for metadata,
    checks for previous runs, and produces an audit plan.

    Args:
        state: Current global audit state.

    Returns:
        State update dict with audit_plan, run_id, and agent_traces.
    """
    tracer = get_tracer()
    tracer.start_agent("orchestrator", f"Planning audit for: {state['repo_path']}")

    try:
        repo_path = state["repo_path"]

        # Step 1: Get repo info via git_analyzer tool
        repo_info_raw = git_analyzer.invoke({
            "repo_path": repo_path,
            "operation": "repo_info",
        })
        repo_info = json.loads(repo_info_raw)
        tracer.log_tool_call("orchestrator", "git_analyzer", {"operation": "repo_info"}, f"Got repo info: {repo_info.get('status')}")

        # Step 2: Get recently changed files
        recent_raw = git_analyzer.invoke({
            "repo_path": repo_path,
            "operation": "recent_changes",
            "params": {"limit": 10},
        })
        recent = json.loads(recent_raw)
        tracer.log_tool_call("orchestrator", "git_analyzer", {"operation": "recent_changes"}, f"Got {len(recent.get('data', []))} changed files")

        # Step 3: Check for previous audit runs
        previous_runs = get_previous_runs(repo_path)
        tracer.log_tool_call("orchestrator", "sqlite_query", {"operation": "get_previous_runs"}, f"Found {len(previous_runs)} previous runs")

        # Step 4: Build audit plan using LLM
        repo_data = repo_info.get("data", {})
        source_files = repo_data.get("source_files", [])
        recent_files = [r["file_path"] for r in recent.get("data", [])]

        # Prioritize recently changed source files
        priority_files = []
        for f in recent_files:
            if f in source_files and f not in priority_files:
                priority_files.append(f)
        # Fill remaining with other source files
        for f in source_files:
            if f not in priority_files:
                priority_files.append(f)
            if len(priority_files) >= 20:
                break

        language = repo_data.get("language", "unknown")
        framework = repo_data.get("framework", "unknown")
        repo_name = repo_data.get("repo_name", "unknown")
        commit_hash = repo_data.get("commit_hash", "unknown")
        branch = repo_data.get("branch", "main")

        # Create audit run in database
        run_id = create_audit_run(
            repo_path=repo_path,
            repo_name=repo_name,
            commit_hash=commit_hash,
            branch=branch,
            language=language,
            framework=framework,
        )

        # Build the plan
        audit_plan = {
            "language": language,
            "framework": framework,
            "total_files": repo_data.get("total_files", 0),
            "priority_files": priority_files,
            "prioritization_reason": "Files ranked by recent change frequency",
            "run_code_quality": True,
            "run_security": True,
            "previous_audit_exists": len(previous_runs) > 0,
            "previous_run_id": previous_runs[0]["id"] if previous_runs else None,
            "notes": f"{language} project using {framework}. {len(priority_files)} files prioritized for audit.",
        }

        trace = tracer.end_agent("orchestrator", f"Plan complete: {len(priority_files)} files, language={language}")

        return {
            "audit_plan": audit_plan,
            "run_id": run_id,
            "agent_traces": [trace],
        }

    except Exception as e:
        trace = tracer.end_agent("orchestrator", "", error=str(e))
        return {
            "audit_plan": {
                "language": "unknown",
                "framework": "unknown",
                "total_files": 0,
                "priority_files": [],
                "prioritization_reason": "Error during planning",
                "run_code_quality": True,
                "run_security": True,
                "previous_audit_exists": False,
                "previous_run_id": None,
                "notes": f"Planning failed: {e}",
            },
            "agent_traces": [trace],
            "errors": [{"agent": "orchestrator", "error": str(e)}],
        }


def merge_and_report(state: AuditState) -> dict:
    """Orchestrator merge phase — combine findings and generate report.

    Deduplicates findings from Code Quality and Security agents,
    persists to database, and generates the final Markdown report.

    Args:
        state: Current state with code_quality_findings and security_findings.

    Returns:
        State update with merged_findings and final_report_path.
    """
    tracer = get_tracer()
    tracer.start_agent("orchestrator_merge", "Merging findings from all agents")

    try:
        cq_findings = state.get("code_quality_findings", [])
        sec_findings = state.get("security_findings", [])
        audit_plan = state.get("audit_plan", {})
        run_id = state.get("run_id", 0)
        repo_path = state["repo_path"]

        # Deduplicate by file + line_start + category
        seen = set()
        merged: list[dict] = []
        for f in cq_findings + sec_findings:
            key = f"{f.get('file', '')}:{f.get('line_start', 0)}:{f.get('category', '')}"
            if key not in seen:
                seen.add(key)
                merged.append(f)

        tracer.log_tool_call("orchestrator_merge", "dedup", {}, f"Deduplicated: {len(cq_findings) + len(sec_findings)} → {len(merged)}")

        # Persist findings to database
        if run_id:
            insert_findings_batch(run_id, merged)
            update_audit_run_counts(run_id, merged)
            tracer.log_tool_call("orchestrator_merge", "sqlite_insert", {}, f"Inserted {len(merged)} findings")

        # Generate report
        repo_name = audit_plan.get("framework", "repo")
        if repo_name == "unknown":
            repo_name = state.get("repo_path", "").split("/")[-1].split("\\")[-1]

        report_result_raw = generate_report.invoke({
            "repo_name": repo_name,
            "repo_path": repo_path,
            "code_quality_findings": json.dumps(cq_findings),
            "security_findings": json.dumps(sec_findings),
            "refactoring_plan": "[]",  # Will be filled after refactoring agent
        })
        report_result = json.loads(report_result_raw)
        report_path = report_result.get("data", {}).get("report_path", "")

        tracer.log_tool_call("orchestrator_merge", "report_generator", {}, f"Report: {report_path}")

        trace = tracer.end_agent("orchestrator_merge", f"Merged {len(merged)} findings, report at {report_path}")

        return {
            "merged_findings": merged,
            "final_report_path": report_path,
            "agent_traces": [trace],
        }

    except Exception as e:
        trace = tracer.end_agent("orchestrator_merge", "", error=str(e))
        return {
            "merged_findings": [],
            "final_report_path": "",
            "agent_traces": [trace],
            "errors": [{"agent": "orchestrator_merge", "error": str(e)}],
        }


def route_after_planning(state: AuditState) -> Literal["run_both", "skip_quality", "skip_security"]:
    """Decide which specialist agents to invoke based on the audit plan.

    Args:
        state: Current state after orchestrator planning.

    Returns:
        Routing key for conditional edges.
    """
    plan = state.get("audit_plan", {})

    run_quality = plan.get("run_code_quality", True)
    run_security = plan.get("run_security", True)

    if not run_quality and run_security:
        return "skip_quality"
    if run_quality and not run_security:
        return "skip_security"

    return "run_both"
