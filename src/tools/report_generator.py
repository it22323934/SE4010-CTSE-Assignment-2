"""Markdown report generator tool for CodeSentinel.

Used by the Orchestrator in the final step to compile all findings
into a structured, readable Markdown report and persist to SQLite.
"""

import json
from datetime import datetime
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from src.config import REPORTS_DIR


class ReportGeneratorInput(BaseModel):
    """Input schema for the report generator tool."""

    repo_name: str = Field(
        ...,
        description="Name of the repository being audited.",
    )
    repo_path: str = Field(
        ...,
        description="Absolute path to the repository.",
    )
    code_quality_findings: str = Field(
        ...,
        description="JSON string of code quality findings.",
    )
    security_findings: str = Field(
        ...,
        description="JSON string of security vulnerability findings.",
    )
    refactoring_plan: str = Field(
        ...,
        description="JSON string of prioritized refactoring actions.",
    )
    output_dir: str | None = Field(
        default=None,
        description="Optional output directory. Defaults to project reports/ folder.",
    )


def _severity_emoji(severity: str) -> str:
    """Return an emoji indicator for severity level.

    Args:
        severity: Severity string.

    Returns:
        Emoji string.
    """
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
    }.get(severity, "⚪")


def _build_report(
    repo_name: str,
    repo_path: str,
    cq_findings: list[dict],
    sec_findings: list[dict],
    refactoring: list[dict],
) -> str:
    """Build the full Markdown report content.

    Args:
        repo_name: Repository name.
        repo_path: Repository path.
        cq_findings: Code quality findings.
        sec_findings: Security findings.
        refactoring: Refactoring plan.

    Returns:
        Complete Markdown report as a string.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_findings = cq_findings + sec_findings
    total = len(all_findings)
    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    medium = sum(1 for f in all_findings if f.get("severity") == "medium")
    low = sum(1 for f in all_findings if f.get("severity") == "low")

    sections: list[str] = []

    # Header
    sections.append(f"# 🛡️ CodeSentinel Audit Report")
    sections.append(f"\n**Repository:** `{repo_name}` (`{repo_path}`)")
    sections.append(f"**Generated:** {now}")
    sections.append(f"**Total Findings:** {total}")
    sections.append("")

    # Executive Summary
    sections.append("## Executive Summary")
    sections.append("")
    sections.append("| Severity | Count |")
    sections.append("|----------|-------|")
    sections.append(f"| 🔴 Critical | {critical} |")
    sections.append(f"| 🟠 High | {high} |")
    sections.append(f"| 🟡 Medium | {medium} |")
    sections.append(f"| 🔵 Low | {low} |")
    sections.append(f"| **Total** | **{total}** |")
    sections.append("")

    # Code Quality Findings
    if cq_findings:
        sections.append("## Code Quality Findings")
        sections.append("")
        for f in sorted(cq_findings, key=lambda x: ["critical", "high", "medium", "low"].index(x.get("severity", "low"))):
            emoji = _severity_emoji(f.get("severity", "low"))
            sections.append(f"### {emoji} {f.get('id', 'N/A')} — {f.get('category', 'Unknown')}")
            sections.append(f"- **File:** `{f.get('file', 'unknown')}`")
            if f.get("line_start"):
                sections.append(f"- **Lines:** {f['line_start']}–{f.get('line_end', f['line_start'])}")
            sections.append(f"- **Severity:** {f.get('severity', 'unknown')}")
            sections.append(f"- **Confidence:** {f.get('confidence', 0):.0%}")
            sections.append(f"- **Description:** {f.get('description', '')}")
            if f.get("suggestion"):
                sections.append(f"- **Suggestion:** {f['suggestion']}")
            sections.append("")

    # Security Findings
    if sec_findings:
        sections.append("## Security Vulnerabilities")
        sections.append("")
        for f in sorted(sec_findings, key=lambda x: ["critical", "high", "medium", "low"].index(x.get("severity", "low"))):
            emoji = _severity_emoji(f.get("severity", "low"))
            sections.append(f"### {emoji} {f.get('id', 'N/A')} — {f.get('category', 'Unknown')}")
            sections.append(f"- **File:** `{f.get('file', 'unknown')}`")
            if f.get("line_start"):
                sections.append(f"- **Lines:** {f['line_start']}–{f.get('line_end', f['line_start'])}")
            sections.append(f"- **Severity:** {f.get('severity', 'unknown')}")
            if f.get("cwe_id"):
                sections.append(f"- **CWE:** {f['cwe_id']}")
            sections.append(f"- **Confidence:** {f.get('confidence', 0):.0%}")
            sections.append(f"- **Description:** {f.get('description', '')}")
            if f.get("attack_vector"):
                sections.append(f"- **Attack Vector:** {f['attack_vector']}")
            if f.get("suggestion"):
                sections.append(f"- **Recommendation:** {f['suggestion']}")
            sections.append("")

    # Refactoring Plan
    if refactoring:
        sections.append("## Prioritized Refactoring Plan")
        sections.append("")
        sections.append("| Priority | Title | File | Addresses |")
        sections.append("|----------|-------|------|-----------|")
        for r in sorted(refactoring, key=lambda x: x.get("priority", 99)):
            refs = ", ".join(r.get("finding_refs", []))
            sections.append(f"| {r.get('priority', '-')} | {r.get('title', '')} | `{r.get('file', '')}` | {refs} |")
        sections.append("")

        for r in sorted(refactoring, key=lambda x: x.get("priority", 99)):
            sections.append(f"### Priority {r.get('priority', '-')}: {r.get('title', '')}")
            sections.append(f"**File:** `{r.get('file', '')}`")
            if r.get("rationale"):
                sections.append(f"**Rationale:** {r['rationale']}")
            if r.get("changes_summary"):
                sections.append(f"**Changes:** {r['changes_summary']}")
            if r.get("before"):
                sections.append("\n**Before:**")
                sections.append(f"```python\n{r['before']}\n```")
            if r.get("after"):
                sections.append("\n**After:**")
                sections.append(f"```python\n{r['after']}\n```")
            sections.append("")

    # Footer
    sections.append("---")
    sections.append(f"*Report generated by CodeSentinel v1.0.0 on {now}*")

    return "\n".join(sections)


@tool(args_schema=ReportGeneratorInput)
def generate_report(
    repo_name: str,
    repo_path: str,
    code_quality_findings: str,
    security_findings: str,
    refactoring_plan: str,
    output_dir: str | None = None,
) -> str:
    """Generate a comprehensive Markdown audit report and save to disk.

    Creates a structured report with executive summary, severity counts,
    code quality findings, security vulnerabilities with CWE references,
    and a prioritized refactoring plan with before/after code snippets.

    Args:
        repo_name: Name of the repository.
        repo_path: Absolute path to the repository.
        code_quality_findings: JSON string of code quality findings.
        security_findings: JSON string of security findings.
        refactoring_plan: JSON string of refactoring actions.
        output_dir: Optional custom output directory.

    Returns:
        JSON string with the report file path and summary stats.

    Raises:
        ValueError: If findings JSON is malformed.
    """
    try:
        cq_findings = json.loads(code_quality_findings) if code_quality_findings else []
        sec_findings = json.loads(security_findings) if security_findings else []
        refactoring = json.loads(refactoring_plan) if refactoring_plan else []

        report_content = _build_report(repo_name, repo_path, cq_findings, sec_findings, refactoring)

        # Write report to file
        out_dir = Path(output_dir) if output_dir else REPORTS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        report_path = out_dir / f"audit_{repo_name}_{timestamp}.md"
        report_path.write_text(report_content, encoding="utf-8")

        all_findings = cq_findings + sec_findings
        return json.dumps(
            {
                "status": "success",
                "data": {
                    "report_path": str(report_path),
                    "total_findings": len(all_findings),
                    "critical_count": sum(1 for f in all_findings if f.get("severity") == "critical"),
                    "high_count": sum(1 for f in all_findings if f.get("severity") == "high"),
                    "medium_count": sum(1 for f in all_findings if f.get("severity") == "medium"),
                    "low_count": sum(1 for f in all_findings if f.get("severity") == "low"),
                    "refactoring_actions": len(refactoring),
                    "report_lines": len(report_content.split("\n")),
                },
                "metadata": {"tool": "report_generator", "repo": repo_name},
            },
            indent=2,
        )

    except json.JSONDecodeError as e:
        return json.dumps({"status": "error", "error": f"Invalid JSON input: {e}", "tool": "report_generator"})
    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "report_generator"})
