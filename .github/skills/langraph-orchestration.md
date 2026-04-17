# Skill: LangGraph Orchestration for CodeSentinel

## LangGraph Workflow Pattern

CodeSentinel uses a **conditional fan-out / fan-in** pattern, NOT a simple linear chain. The Orchestrator delegates to specialist agents, collects results, and can re-route if critical findings need cross-referencing.

## Graph Definition Blueprint

```python
# src/graph.py

import operator
from typing import Annotated, TypedDict, Literal
from langgraph.graph import StateGraph, END, START
from langgraph.checkpoint.sqlite import SqliteSaver

from src.state import AuditState
from src.agents.orchestrator import orchestrator_node, route_after_planning, merge_and_report
from src.agents.code_quality import code_quality_node
from src.agents.security import security_node
from src.agents.refactoring import refactoring_node


def build_graph() -> StateGraph:
    """Build the CodeSentinel LangGraph workflow.

    Workflow:
        1. Orchestrator analyzes repo → builds audit plan
        2. Fan-out: Code Quality + Security agents run (can be parallel)
        3. Orchestrator merges findings, checks for cross-references
        4. Refactoring Agent generates fix suggestions
        5. Orchestrator compiles final report

    Returns:
        Compiled LangGraph StateGraph ready for invocation.
    """
    workflow = StateGraph(AuditState)

    # --- Add Nodes ---
    workflow.add_node("orchestrator_plan", orchestrator_node)
    workflow.add_node("code_quality", code_quality_node)
    workflow.add_node("security", security_node)
    workflow.add_node("merge_findings", merge_and_report)
    workflow.add_node("refactoring", refactoring_node)

    # --- Define Edges ---

    # START → Orchestrator plans the audit
    workflow.add_edge(START, "orchestrator_plan")

    # Orchestrator → fan-out to both specialist agents
    # Use conditional edge if you want orchestrator to skip agents
    workflow.add_conditional_edges(
        "orchestrator_plan",
        route_after_planning,
        {
            "run_both": "code_quality",       # Default: run both
            "skip_quality": "security",        # If only security needed
            "skip_security": "code_quality",   # If only quality needed
        }
    )

    # Both specialists → merge node
    # For true parallelism, use Send() API
    workflow.add_edge("code_quality", "security")
    workflow.add_edge("security", "merge_findings")

    # Merge → Refactoring (always runs after merge)
    workflow.add_edge("merge_findings", "refactoring")

    # Refactoring → END
    workflow.add_edge("refactoring", END)

    # --- Compile with checkpointing ---
    memory = SqliteSaver.from_conn_string("data/checkpoints.db")
    return workflow.compile(checkpointer=memory)
```

## Advanced: Parallel Execution with Send()

If you want Code Quality and Security to run truly in parallel (bonus complexity):

```python
from langgraph.constants import Send

def fan_out_to_specialists(state: AuditState) -> list[Send]:
    """Route to both specialist agents in parallel."""
    sends = []
    if state.get("audit_plan", {}).get("run_code_quality", True):
        sends.append(Send("code_quality", state))
    if state.get("audit_plan", {}).get("run_security", True):
        sends.append(Send("security", state))
    return sends

# In graph definition:
workflow.add_conditional_edges("orchestrator_plan", fan_out_to_specialists)
```

## Agent Node Pattern

Every agent node function MUST follow this exact signature:

```python
from src.state import AuditState

def my_agent_node(state: AuditState) -> dict:
    """Process state and return updates.

    Args:
        state: Current global audit state.

    Returns:
        Dictionary with ONLY the state keys this agent updates.
        LangGraph merges this into the global state automatically.
    """
    # 1. Read what you need from state
    repo_path = state["repo_path"]
    plan = state.get("audit_plan", {})

    # 2. Do your work (call LLM, run tools)
    result = do_agent_work(repo_path, plan)

    # 3. Return ONLY your updates
    return {
        "my_findings": result,
        "agent_trace": [{"agent": "my_agent", "output": result}]
    }
```

## Conditional Routing Pattern

```python
def route_after_planning(state: AuditState) -> Literal["run_both", "skip_quality", "skip_security"]:
    """Decide which specialist agents to invoke based on the audit plan.

    The orchestrator may skip an agent if the repo has characteristics
    that make one analysis unnecessary (e.g., no SQL in the project
    means skip SQL injection scanning).

    Args:
        state: Current state after orchestrator planning.

    Returns:
        Routing key for conditional edges.
    """
    plan = state.get("audit_plan", {})
    language = plan.get("language", "unknown")

    # Example: skip security for pure documentation repos
    if plan.get("is_docs_only", False):
        return "skip_security"

    return "run_both"
```

## Checkpointing & Resume

LangGraph's SqliteSaver lets you resume interrupted audits:

```python
# Run with a thread_id for checkpointing
config = {"configurable": {"thread_id": f"audit-{repo_name}-{timestamp}"}}
result = graph.invoke(initial_state, config=config)
```

## Error Handling in Nodes

Never let an agent node crash the graph. Wrap everything:

```python
def code_quality_node(state: AuditState) -> dict:
    try:
        findings = run_code_quality_analysis(state)
        return {"code_quality_findings": findings}
    except Exception as e:
        logger.error(f"Code Quality agent failed: {e}")
        return {
            "code_quality_findings": [],
            "errors": [{"agent": "code_quality", "error": str(e)}]
        }
```

## Key LangGraph Concepts for This Project

1. **StateGraph** — the core graph type where nodes share a typed state dict
2. **Nodes** — Python functions that take state, return state updates
3. **Edges** — connections between nodes (unconditional or conditional)
4. **Conditional Edges** — routing functions that return the next node name
5. **Checkpointer** — persistence layer for resuming interrupted runs
6. **Send()** — API for dynamic fan-out to parallel nodes
7. **Annotated reducers** — `Annotated[list, operator.add]` for accumulating lists across nodes