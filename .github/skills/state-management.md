# Skill: State Management for CodeSentinel

## Core Concept

In LangGraph, state is a **TypedDict** that flows through every node. Each agent node receives the full state and returns a partial update dict. LangGraph merges updates automatically. This is how context is preserved across agents without losing data.

## The AuditState Schema

```python
# src/state.py

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
from typing import Annotated, Any, TypedDict
from dataclasses import dataclass, field


class FileInfo(TypedDict):
    """Metadata about a single file in the repository."""
    path: str
    language: str
    lines: int
    last_modified_commit: str
    change_frequency: int  # Number of commits touching this file


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
    id: str                   # Auto-generated unique ID
    file: str                 # File path
    line_start: int
    line_end: int
    category: str             # e.g., "long_function", "sql_injection"
    agent_source: str         # "code_quality" | "security"
    severity: str             # "critical" | "high" | "medium" | "low"
    cwe_id: str | None        # CWE reference (security only)
    description: str
    suggestion: str | None
    confidence: float         # 0.0 to 1.0
    is_new: bool | None       # True if not seen in previous audit


class RefactoringAction(TypedDict):
    """A concrete refactoring suggestion."""
    priority: int
    finding_refs: list[str]   # IDs of findings this addresses
    file: str
    title: str
    rationale: str
    before: str               # Code before refactoring
    after: str                # Code after refactoring
    changes_summary: str
    depends_on: list[int]     # Priority numbers of prerequisite actions


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

    This is the single source of truth flowing through the LangGraph workflow.
    Each agent reads from and writes to specific fields.

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

    # --- Input (set before graph invocation) ---
    repo_path: str
    run_id: int

    # --- Orchestrator outputs ---
    audit_plan: AuditPlan
    merged_findings: list[Finding]
    final_report_path: str

    # --- Code Quality Agent outputs ---
    code_quality_findings: Annotated[list[Finding], operator.add]

    # --- Security Agent outputs ---
    security_findings: Annotated[list[Finding], operator.add]

    # --- Refactoring Agent outputs ---
    refactoring_plan: list[RefactoringAction]

    # --- Cross-cutting concerns ---
    agent_traces: Annotated[list[AgentTrace], operator.add]
    errors: Annotated[list[dict], operator.add]
```

## Why `Annotated[list, operator.add]`?

Without the annotation, if two agents both write to the same list field, the second write would **overwrite** the first. With `operator.add`, LangGraph **concatenates** the lists instead.

```python
# WITHOUT operator.add:
# Agent A returns: {"findings": [finding_1]}
# Agent B returns: {"findings": [finding_2]}
# Final state: {"findings": [finding_2]}  ← Agent A's finding is LOST

# WITH Annotated[list, operator.add]:
# Agent A returns: {"findings": [finding_1]}
# Agent B returns: {"findings": [finding_2]}
# Final state: {"findings": [finding_1, finding_2]}  ← Both preserved
```

## How Each Agent Interacts with State

### Orchestrator (Planning Phase)
```python
def orchestrator_node(state: AuditState) -> dict:
    """Orchestrator reads repo_path, writes audit_plan."""
    repo_path = state["repo_path"]

    # Call tools, analyze repo
    plan = analyze_repo(repo_path)

    return {
        "audit_plan": plan,
        "agent_traces": [{
            "agent": "orchestrator",
            "timestamp": datetime.now().isoformat(),
            "tool_calls": [{"tool": "git_analyzer", "params": {"repo_path": repo_path}}],
            "input_summary": f"Repo: {repo_path}",
            "output_summary": f"Plan: {plan['language']} project, {plan['total_files']} files",
            "duration_ms": 1200,
            "error": None,
        }]
    }
```

### Code Quality Agent
```python
def code_quality_node(state: AuditState) -> dict:
    """Code Quality reads audit_plan.priority_files, writes code_quality_findings."""
    plan = state["audit_plan"]
    priority_files = plan["priority_files"]

    findings = []
    for file_path in priority_files:
        # Call AST parser tool
        ast_result = parse_ast_tool.invoke({"file_path": file_path})
        # Feed to LLM for analysis
        agent_findings = analyze_with_llm(ast_result)
        findings.extend(agent_findings)

    return {
        "code_quality_findings": findings,  # Appended via operator.add
        "agent_traces": [{...}]
    }
```

### Security Agent
```python
def security_node(state: AuditState) -> dict:
    """Security reads audit_plan.priority_files, writes security_findings."""
    plan = state["audit_plan"]
    priority_files = plan["priority_files"]

    findings = []
    for file_path in priority_files:
        scan_result = pattern_scanner.invoke({"file_path": file_path})
        history_result = git_analyzer.invoke({
            "repo_path": state["repo_path"],
            "operation": "search_history",
            "params": {"pattern": "password|secret|api_key"}
        })
        agent_findings = classify_with_llm(scan_result, history_result)
        findings.extend(agent_findings)

    return {
        "security_findings": findings,
        "agent_traces": [{...}]
    }
```

### Merge Step (Orchestrator Again)
```python
def merge_and_report(state: AuditState) -> dict:
    """Orchestrator merges findings from both agents, deduplicates, cross-references."""
    cq_findings = state.get("code_quality_findings", [])
    sec_findings = state.get("security_findings", [])

    # Cross-reference: if same file flagged by both, escalate severity
    merged = deduplicate_and_cross_reference(cq_findings, sec_findings)

    return {
        "merged_findings": merged,
        "agent_traces": [{...}]
    }
```

### Refactoring Agent
```python
def refactoring_node(state: AuditState) -> dict:
    """Refactoring reads merged_findings, writes refactoring_plan."""
    merged = state["merged_findings"]
    plan = state["audit_plan"]

    refactoring_actions = generate_refactoring_plan(merged, plan)

    return {
        "refactoring_plan": refactoring_actions,
        "agent_traces": [{...}]
    }
```

## State Flow Visualization

```
┌─ Initial State ────────────────────────────────────────┐
│ repo_path: "/path/to/repo"                              │
│ run_id: 1                                               │
│ (everything else empty)                                 │
└────────────────────┬───────────────────────────────────-┘
                     │
                     ▼
┌─ After Orchestrator ───────────────────────────────────-┐
│ + audit_plan: {language: "python", files: [...]}        │
│ + agent_traces: [orchestrator_trace]                    │
└────────────────────┬───────────────────────────────────-┘
                     │
              ┌──────┴───────┐
              ▼              ▼
┌─ After CQ ──────┐  ┌─ After Sec ─────┐
│ + cq_findings:   │  │ + sec_findings:  │
│   [f1, f2, f3]   │  │   [f4, f5]       │
│ + traces: [+1]   │  │ + traces: [+1]   │
└────────┬─────────┘  └────────┬─────────┘
         │                     │
         └──────────┬──────────┘
                    ▼
┌─ After Merge ──────────────────────────────────────────┐
│ + merged_findings: [f1, f2_escalated, f3, f4, f5]      │
│ + traces: [+1]                                          │
└────────────────────┬───────────────────────────────────-┘
                     │
                     ▼
┌─ After Refactoring ────────────────────────────────────┐
│ + refactoring_plan: [action1, action2, ...]             │
│ + final_report_path: "reports/audit_2024-01-15.md"      │
│ + traces: [+1]                                          │
└────────────────────────────────────────────────────────-┘
```

## Anti-Patterns to Avoid

1. **Never mutate state directly** — Always return a new dict. LangGraph manages merging.
2. **Never store raw LLM responses in state** — Parse them first. If parsing fails, store an error.
3. **Never use state for configuration** — Config goes in `config.py`. State is for runtime data only.
4. **Never skip the trace** — Every agent return MUST include an `agent_traces` entry.
5. **Never store large binary data in state** — Store file paths, not file contents.