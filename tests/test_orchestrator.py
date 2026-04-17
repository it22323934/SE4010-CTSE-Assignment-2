"""Tests for the Orchestrator agent.

Tests route_after_planning (deterministic) and orchestrator_node behavior
without requiring live LLM connections.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.agents.orchestrator import merge_and_report, route_after_planning


class TestRouteAfterPlanning:
    """Test the conditional routing function."""

    def test_run_both(self):
        """Should route to 'run_both' when both agents enabled."""
        state = {
            "audit_plan": {
                "run_code_quality": True,
                "run_security": True,
            }
        }
        assert route_after_planning(state) == "run_both"

    def test_skip_quality(self):
        """Should route to 'skip_quality' when code quality disabled."""
        state = {
            "audit_plan": {
                "run_code_quality": False,
                "run_security": True,
            }
        }
        assert route_after_planning(state) == "skip_quality"

    def test_skip_security(self):
        """Should route to 'skip_security' when security disabled."""
        state = {
            "audit_plan": {
                "run_code_quality": True,
                "run_security": False,
            }
        }
        assert route_after_planning(state) == "skip_security"

    def test_missing_plan_defaults_to_run_both(self):
        """Should default to 'run_both' if plan is missing."""
        state = {}
        assert route_after_planning(state) == "run_both"


class TestMergeAndReport:
    """Test the merge_and_report node."""

    @patch("src.agents.orchestrator.insert_findings_batch")
    @patch("src.agents.orchestrator.update_audit_run_counts")
    @patch("src.agents.orchestrator.generate_report")
    def test_merge_deduplicates(
        self,
        mock_report,
        mock_update_counts,
        mock_insert_batch,
        mock_findings,
        mock_audit_plan,
    ):
        """Should deduplicate findings from multiple agents."""
        mock_insert_batch.return_value = [1, 2, 3]
        mock_report.invoke = MagicMock(return_value=json.dumps({
            "status": "success",
            "data": {"report_path": "/tmp/report.md"},
        }))

        state = {
            "code_quality_findings": [mock_findings[0]],
            "security_findings": [mock_findings[1], mock_findings[2]],
            "audit_plan": mock_audit_plan,
            "run_id": 1,
            "repo_path": "/tmp/test-repo",
        }

        result = merge_and_report(state)

        assert "merged_findings" in result
        assert len(result["merged_findings"]) == 3
        assert "agent_traces" in result

    @patch("src.agents.orchestrator.insert_findings_batch")
    @patch("src.agents.orchestrator.update_audit_run_counts")
    @patch("src.agents.orchestrator.generate_report")
    def test_merge_handles_empty_findings(
        self,
        mock_report,
        mock_update_counts,
        mock_insert_batch,
        mock_audit_plan,
    ):
        """Should handle case with zero findings."""
        mock_insert_batch.return_value = []
        mock_report.invoke = MagicMock(return_value=json.dumps({
            "status": "success",
            "data": {"report_path": "/tmp/report.md"},
        }))

        state = {
            "code_quality_findings": [],
            "security_findings": [],
            "audit_plan": mock_audit_plan,
            "run_id": 1,
            "repo_path": "/tmp/test-repo",
        }

        result = merge_and_report(state)

        assert result["merged_findings"] == []
