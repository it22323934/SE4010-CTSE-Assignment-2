"""LangGraph workflow definition for CodeSentinel.

Defines the multi-agent pipeline: Orchestrator → Code Quality + Security → Merge → Refactoring.
Uses conditional fan-out based on the audit plan and sequential merge → refactoring.
"""

from langgraph.graph import END, START, StateGraph

from src.agents.code_quality import code_quality_node
from src.agents.orchestrator import merge_and_report, orchestrator_node, route_after_planning
from src.agents.refactoring import refactoring_node
from src.agents.security import security_node
from src.state import AuditState


def build_graph() -> StateGraph:
    """Build the CodeSentinel LangGraph workflow.

    Workflow:
        1. Orchestrator analyzes repo → builds audit plan
        2. Fan-out: Code Quality + Security agents run sequentially
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

    # Orchestrator → conditional routing based on audit plan
    workflow.add_conditional_edges(
        "orchestrator_plan",
        route_after_planning,
        {
            "run_both": "code_quality",
            "skip_quality": "security",
            "skip_security": "code_quality",
        },
    )

    # Code Quality → Security (sequential for simplicity)
    workflow.add_edge("code_quality", "security")

    # Security → Merge
    workflow.add_edge("security", "merge_findings")

    # Merge → Refactoring
    workflow.add_edge("merge_findings", "refactoring")

    # Refactoring → END
    workflow.add_edge("refactoring", END)

    # --- Compile ---
    return workflow.compile()
