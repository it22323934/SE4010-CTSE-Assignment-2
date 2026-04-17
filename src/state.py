"""Global state schema for the CodeSentinel multi-agent audit pipeline.

This TypedDict defines every field that flows through the LangGraph workflow.
Agents read what they need and return updates for their fields only.
LangGraph handles the merge.

Key design decisions:
- List fields use Annotated[list, operator.add] so multiple agents can append
- Each agent writes to its own namespace (no field collisions)
- The orchestrator is the only agent that reads ALL fields
"""

import operator
from typing import Annotated, TypedDict


class FileInfo(TypedDict):
    """Metadata about a single file in the repository."""

    path: str
    language: str
    lines: int
    last_modified_commit: str
    change_frequency: int


class AuditPlan(TypedDict):
    """Output of the Orchestrator's planning phase."""

    language: str
    framework: str
    total_files: int
    priority_files: list[str]
    prioritization_reason: str
    run_code_quality: bool
    run_security: bool
    previous_audit_exists: bool
    previous_run_id: int | None
    notes: str


class Finding(TypedDict):
    """A single audit finding from any agent."""

    id: str
    file: str
    line_start: int
    line_end: int
    category: str
    agent_source: str
    severity: str
    cwe_id: str | None
    description: str
    suggestion: str | None
    confidence: float
    is_new: bool | None


class RefactoringAction(TypedDict):
    """A concrete refactoring suggestion."""

    priority: int
    finding_refs: list[str]
    file: str
    title: str
    rationale: str
    before: str
    after: str
    changes_summary: str
    depends_on: list[int]


class AgentTrace(TypedDict):
    """Execution trace entry for observability."""

    agent: str
    timestamp: str
    tool_calls: list[dict]
    input_summary: str
    output_summary: str
    duration_ms: int
    error: str | None


class AuditState(TypedDict):
    """Global state for the CodeSentinel audit pipeline.

    Field ownership:
    - repo_path, run_id: Set at invocation time (main.py)
    - audit_plan: Written by Orchestrator
    - code_quality_findings: Written by Code Quality Agent
    - security_findings: Written by Security Agent
    - merged_findings: Written by Orchestrator (merge step)
    - refactoring_plan: Written by Refactoring Agent
    - final_report_path: Written by Report Generator
    - agent_traces: Appended by ALL agents (observability)
    - errors: Appended by any agent that encounters issues
    """

    # Input (set before graph invocation)
    repo_path: str
    run_id: int

    # Orchestrator outputs
    audit_plan: AuditPlan
    merged_findings: list[Finding]
    final_report_path: str

    # Code Quality Agent outputs — accumulates via operator.add
    code_quality_findings: Annotated[list[Finding], operator.add]

    # Security Agent outputs — accumulates via operator.add
    security_findings: Annotated[list[Finding], operator.add]

    # Refactoring Agent outputs
    refactoring_plan: list[RefactoringAction]

    # Cross-cutting — all agents append here
    agent_traces: Annotated[list[AgentTrace], operator.add]
    errors: Annotated[list[dict], operator.add]
