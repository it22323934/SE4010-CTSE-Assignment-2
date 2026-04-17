"""End-to-end integration test for the CodeSentinel pipeline.

Tests the full LangGraph workflow with mocked LLM calls, verifying
state flows correctly through all agents.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestGraphBuild:
    """Test that the graph compiles correctly."""

    def test_graph_compiles(self):
        """Graph should compile without errors."""
        from src.graph import build_graph

        graph = build_graph()
        assert graph is not None

    def test_graph_has_required_nodes(self):
        """Graph should contain all 5 expected nodes."""
        from src.graph import build_graph

        graph = build_graph()
        # The compiled graph should have the nodes
        node_names = set(graph.get_graph().nodes.keys())
        expected = {"orchestrator_plan", "code_quality", "security", "merge_findings", "refactoring"}
        # LangGraph adds __start__ and __end__
        assert expected.issubset(node_names)


class TestPipelineIntegration:
    """End-to-end pipeline test with mocked LLM."""

    @patch("src.agents.refactoring.ChatOllama")
    @patch("src.agents.security.ChatOllama")
    @patch("src.agents.code_quality.ChatOllama")
    @patch("src.agents.orchestrator.ChatOllama")
    @patch("src.agents.orchestrator.create_audit_run")
    @patch("src.agents.orchestrator.get_previous_runs")
    @patch("src.agents.orchestrator.insert_findings_batch")
    @patch("src.agents.orchestrator.update_audit_run_counts")
    @patch("src.agents.refactoring.insert_refactoring_action")
    def test_full_pipeline(
        self,
        mock_insert_action,
        mock_update_counts,
        mock_insert_batch,
        mock_prev_runs,
        mock_create_run,
        mock_orch_ollama,
        mock_cq_ollama,
        mock_sec_ollama,
        mock_ref_ollama,
        sample_repo: Path,
    ):
        """Full pipeline should execute all agents and produce a final state."""
        from src.graph import build_graph

        # Configure mocks
        mock_create_run.return_value = 1
        mock_prev_runs.return_value = []
        mock_insert_batch.return_value = [1, 2, 3]
        mock_insert_action.return_value = 1

        # Mock all LLM calls
        for mock in [mock_orch_ollama, mock_cq_ollama, mock_sec_ollama, mock_ref_ollama]:
            llm = MagicMock()
            llm.invoke.return_value = MagicMock(content="LLM mock response")
            llm.bind_tools.return_value = llm
            mock.return_value = llm

        graph = build_graph()

        initial_state = {
            "repo_path": str(sample_repo),
            "run_id": 0,
            "code_quality_findings": [],
            "security_findings": [],
            "agent_traces": [],
            "errors": [],
        }

        final_state = graph.invoke(initial_state)

        # Verify state structure
        assert "audit_plan" in final_state
        assert "merged_findings" in final_state
        assert "refactoring_plan" in final_state
        assert "agent_traces" in final_state
        assert isinstance(final_state["code_quality_findings"], list)
        assert isinstance(final_state["security_findings"], list)

    @patch("src.agents.refactoring.ChatOllama")
    @patch("src.agents.security.ChatOllama")
    @patch("src.agents.code_quality.ChatOllama")
    @patch("src.agents.orchestrator.ChatOllama")
    @patch("src.agents.orchestrator.create_audit_run")
    @patch("src.agents.orchestrator.get_previous_runs")
    @patch("src.agents.orchestrator.insert_findings_batch")
    @patch("src.agents.orchestrator.update_audit_run_counts")
    @patch("src.agents.refactoring.insert_refactoring_action")
    def test_pipeline_finds_vulnerabilities(
        self,
        mock_insert_action,
        mock_update_counts,
        mock_insert_batch,
        mock_prev_runs,
        mock_create_run,
        mock_orch_ollama,
        mock_cq_ollama,
        mock_sec_ollama,
        mock_ref_ollama,
        sample_repo: Path,
    ):
        """Pipeline should detect real vulnerabilities in sample files."""
        from src.graph import build_graph

        mock_create_run.return_value = 1
        mock_prev_runs.return_value = []
        mock_insert_batch.return_value = list(range(20))
        mock_insert_action.return_value = 1

        for mock in [mock_orch_ollama, mock_cq_ollama, mock_sec_ollama, mock_ref_ollama]:
            llm = MagicMock()
            llm.invoke.return_value = MagicMock(content="mock")
            llm.bind_tools.return_value = llm
            mock.return_value = llm

        graph = build_graph()

        initial_state = {
            "repo_path": str(sample_repo),
            "run_id": 0,
            "code_quality_findings": [],
            "security_findings": [],
            "agent_traces": [],
            "errors": [],
        }

        final_state = graph.invoke(initial_state)

        # Should find security issues in vulnerable.py
        sec = final_state.get("security_findings", [])
        cq = final_state.get("code_quality_findings", [])

        # The sample repo has known issues — these should be detected
        all_findings = sec + cq
        assert len(all_findings) > 0


class TestDatabaseIntegration:
    """Test database operations in a realistic flow."""

    def test_crud_cycle(self, test_db):
        """Should create a run, insert findings, and query them back."""
        from src.db.queries import (
            create_audit_run,
            get_findings_for_run,
            insert_finding,
            update_audit_run_status,
        )

        run_id = create_audit_run(
            repo_path="/tmp/test",
            repo_name="test-repo",
            commit_hash="abc123",
            branch="main",
            language="python",
        )
        assert run_id > 0

        finding_id = insert_finding(run_id, {
            "file": "test.py",
            "line_start": 10,
            "line_end": 15,
            "category": "sql_injection",
            "agent_source": "security",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "SQL injection found",
            "suggestion": "Use parameterized queries",
            "confidence": 0.95,
        })
        assert finding_id > 0

        update_audit_run_status(run_id, "completed")

        findings = get_findings_for_run(run_id)
        assert len(findings) >= 1
        assert findings[0]["category"] == "sql_injection"
