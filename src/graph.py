"""LangGraph workflow definition for CodeSentinel.

Defines the multi-agent pipeline: Orchestrator → Code Quality + Security → Merge → Refactoring.
Uses conditional fan-out based on the audit plan for parallel agent execution.
"""

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from src.agents.code_quality import code_quality_node
from src.agents.orchestrator import merge_and_report, orchestrator_node, route_after_planning
from src.agents.refactoring import refactoring_node
from src.agents.security import security_node
from src.state import AuditState


def _fan_out_agents(state: AuditState) -> list[Send]:
    """Fan-out to code_quality and/or security agents based on audit plan.

    Uses LangGraph Send API for true parallel execution when both agents
    are enabled by the orchestrator.

    Args:
        state: Current state after orchestrator planning.

    Returns:
        List of Send objects targeting the appropriate agent nodes.
    """
    route = route_after_planning(state)

    if route == "run_both":
        return [Send("code_quality", state), Send("security", state)]
    elif route == "skip_quality":
        return [Send("security", state)]
    else:  # skip_security
        return [Send("code_quality", state)]


def build_graph() -> StateGraph:
    """Build the CodeSentinel LangGraph workflow.

    Workflow:
        1. Orchestrator analyzes repo → builds audit plan
        2. Fan-out: Code Quality + Security agents run in parallel
           (conditional — orchestrator can skip either)
        3. Orchestrator merges findings, deduplicates, generates initial report
        4. Refactoring Agent generates fix suggestions
        5. Pipeline completes with final report

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

    # Orchestrator → parallel fan-out to agents via Send API
    workflow.add_conditional_edges("orchestrator_plan", _fan_out_agents)

    # Both agents converge to merge (parallel fan-in)
    workflow.add_edge("code_quality", "merge_findings")
    workflow.add_edge("security", "merge_findings")

    # Merge → Refactoring
    workflow.add_edge("merge_findings", "refactoring")

    # Refactoring → END
    workflow.add_edge("refactoring", END)

    # --- Compile ---
    return workflow.compile()
