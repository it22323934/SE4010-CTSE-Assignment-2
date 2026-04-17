"""Tests for the Refactoring agent.

Tests deterministic plan building without requiring a live LLM.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestBuildRefactoringPlanLocally:
    """Test the deterministic refactoring plan builder."""

    def test_security_before_quality(self, mock_findings):
        """Security findings should be prioritized over code quality."""
        from src.agents.refactoring import _build_refactoring_plan_locally

        plan = _build_refactoring_plan_locally(mock_findings)

        assert len(plan) > 0
        # First item should be security (critical)
        assert plan[0]["file"] == "vulnerable.py"

    def test_critical_before_medium(self, mock_findings):
        """Critical findings should come before medium."""
        from src.agents.refactoring import _build_refactoring_plan_locally

        plan = _build_refactoring_plan_locally(mock_findings)

        priorities = [a["priority"] for a in plan]
        assert priorities == sorted(priorities)

    def test_empty_findings(self):
        """Empty findings should return empty plan."""
        from src.agents.refactoring import _build_refactoring_plan_locally

        plan = _build_refactoring_plan_locally([])
        assert plan == []

    def test_plan_contains_required_fields(self, mock_findings):
        """Each action should have all required fields."""
        from src.agents.refactoring import _build_refactoring_plan_locally

        plan = _build_refactoring_plan_locally(mock_findings)

        for action in plan:
            assert "priority" in action
            assert "file" in action
            assert "title" in action
            assert "rationale" in action
            assert "finding_refs" in action
            assert "changes_summary" in action


class TestRefactoringNode:
    """Test the full refactoring_node with mocked dependencies."""

    @patch("src.agents.refactoring.insert_refactoring_action")
    @patch("src.agents.refactoring.ChatOllama")
    def test_node_produces_plan(self, mock_ollama, mock_insert, mock_findings):
        """Should produce a refactoring plan from merged findings."""
        from src.agents.refactoring import refactoring_node

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="LLM placeholder")
        mock_ollama.return_value = mock_llm
        mock_insert.return_value = 1

        state = {
            "merged_findings": mock_findings,
            "run_id": 1,
            "repo_path": "/tmp/test-repo",
            "audit_plan": {
                "language": "python",
                "framework": "none",
                "total_files": 3,
                "priority_files": [],
                "prioritization_reason": "test",
                "run_code_quality": True,
                "run_security": True,
                "previous_audit_exists": False,
                "previous_run_id": None,
                "notes": "",
            },
        }

        result = refactoring_node(state)

        assert "refactoring_plan" in result
        assert len(result["refactoring_plan"]) > 0
        assert "agent_traces" in result

    @patch("src.agents.refactoring.insert_refactoring_action")
    @patch("src.agents.refactoring.ChatOllama")
    def test_node_handles_no_findings(self, mock_ollama, mock_insert):
        """Should handle empty merged findings gracefully."""
        from src.agents.refactoring import refactoring_node

        mock_llm = MagicMock()
        mock_ollama.return_value = mock_llm
        mock_insert.return_value = 1

        state = {
            "merged_findings": [],
            "run_id": 1,
            "repo_path": "/tmp/test-repo",
            "audit_plan": {
                "language": "python",
                "framework": "none",
                "total_files": 0,
                "priority_files": [],
                "prioritization_reason": "test",
                "run_code_quality": True,
                "run_security": True,
                "previous_audit_exists": False,
                "previous_run_id": None,
                "notes": "",
            },
        }

        result = refactoring_node(state)

        assert result["refactoring_plan"] == []
