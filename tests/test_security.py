"""Tests for the Security Vulnerability agent.

Tests pattern-based detection without requiring a live LLM.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestSecurityNode:
    """Test the security_node with mocked LLM."""

    @patch("src.agents.security.ChatOllama")
    def test_node_detects_hardcoded_secrets(self, mock_ollama, sample_repo: Path, mock_audit_plan):
        """Should detect hardcoded secrets in vulnerable.py."""
        from src.agents.security import security_node

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="LLM classification placeholder")
        mock_ollama.return_value = mock_llm

        mock_audit_plan["priority_files"] = [str(sample_repo / "vulnerable.py")]

        state = {
            "repo_path": str(sample_repo),
            "audit_plan": mock_audit_plan,
        }

        result = security_node(state)

        assert "security_findings" in result
        findings = result["security_findings"]
        assert len(findings) > 0

        # Should contain a hardcoded_secret finding
        categories = [f["category"] for f in findings]
        assert "hardcoded_secret" in categories

    @patch("src.agents.security.ChatOllama")
    def test_node_detects_sql_injection(self, mock_ollama, sample_repo: Path, mock_audit_plan):
        """Should detect SQL injection in vulnerable.py."""
        from src.agents.security import security_node

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="placeholder")
        mock_ollama.return_value = mock_llm

        mock_audit_plan["priority_files"] = [str(sample_repo / "vulnerable.py")]

        state = {
            "repo_path": str(sample_repo),
            "audit_plan": mock_audit_plan,
        }

        result = security_node(state)
        categories = [f["category"] for f in result["security_findings"]]
        assert "sql_injection" in categories

    @patch("src.agents.security.ChatOllama")
    def test_node_clean_file_no_findings(self, mock_ollama, sample_repo: Path, mock_audit_plan):
        """Clean file should produce no security findings."""
        from src.agents.security import security_node

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="placeholder")
        mock_ollama.return_value = mock_llm

        mock_audit_plan["priority_files"] = [str(sample_repo / "clean.py")]

        state = {
            "repo_path": str(sample_repo),
            "audit_plan": mock_audit_plan,
        }

        result = security_node(state)
        assert len(result["security_findings"]) == 0

    @patch("src.agents.security.ChatOllama")
    def test_all_findings_have_agent_source(self, mock_ollama, sample_repo: Path, mock_audit_plan):
        """All findings must be tagged with agent_source='security'."""
        from src.agents.security import security_node

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="placeholder")
        mock_ollama.return_value = mock_llm

        mock_audit_plan["priority_files"] = [str(sample_repo / "vulnerable.py")]

        state = {
            "repo_path": str(sample_repo),
            "audit_plan": mock_audit_plan,
        }

        result = security_node(state)
        for f in result["security_findings"]:
            assert f["agent_source"] == "security"
            assert f["severity"] in ("critical", "high", "medium", "low")

    @patch("src.agents.security.ChatOllama")
    def test_findings_have_cwe_ids(self, mock_ollama, sample_repo: Path, mock_audit_plan):
        """Security findings from pattern scanner should have CWE IDs."""
        from src.agents.security import security_node

        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="placeholder")
        mock_ollama.return_value = mock_llm

        mock_audit_plan["priority_files"] = [str(sample_repo / "vulnerable.py")]

        state = {
            "repo_path": str(sample_repo),
            "audit_plan": mock_audit_plan,
        }

        result = security_node(state)
        cwe_findings = [f for f in result["security_findings"] if f.get("cwe_id")]
        assert len(cwe_findings) > 0
