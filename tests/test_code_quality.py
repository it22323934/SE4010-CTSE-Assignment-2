"""Tests for the Code Quality agent.

Tests the deterministic local analysis (_analyze_file_locally) without
requiring a live LLM. Also tests the full node with mocked LLM.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestAnalyzeFileLocally:
    """Test the deterministic code quality checks."""

    def test_detects_long_function(self, sample_repo: Path):
        """Should flag functions exceeding MAX_FUNCTION_LENGTH."""
        from src.agents.code_quality import _analyze_file_locally
        from src.tools.ast_parser import parse_ast_tool

        ast_result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "messy.py"),
        }))

        findings = _analyze_file_locally(str(sample_repo / "messy.py"), ast_result)

        long_fn_findings = [f for f in findings if f["category"] == "long_function"]
        assert len(long_fn_findings) >= 1
        assert "long_function" in long_fn_findings[0]["description"]

    def test_detects_deep_nesting(self, sample_repo: Path):
        """Should flag functions with excessive nesting depth."""
        from src.agents.code_quality import _analyze_file_locally
        from src.tools.ast_parser import parse_ast_tool

        ast_result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "messy.py"),
        }))

        findings = _analyze_file_locally(str(sample_repo / "messy.py"), ast_result)

        nesting_findings = [f for f in findings if f["category"] == "deep_nesting"]
        assert len(nesting_findings) >= 1

    def test_detects_god_class(self, sample_repo: Path):
        """Should flag classes with too many methods."""
        from src.agents.code_quality import _analyze_file_locally
        from src.tools.ast_parser import parse_ast_tool

        ast_result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "messy.py"),
        }))

        findings = _analyze_file_locally(str(sample_repo / "messy.py"), ast_result)

        god_class_findings = [f for f in findings if f["category"] == "god_class"]
        assert len(god_class_findings) >= 1
        assert "GodObject" in god_class_findings[0]["description"]

    def test_detects_bare_excepts(self, sample_repo: Path):
        """Should flag bare except clauses."""
        from src.agents.code_quality import _analyze_file_locally
        from src.tools.ast_parser import parse_ast_tool

        ast_result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "messy.py"),
        }))

        findings = _analyze_file_locally(str(sample_repo / "messy.py"), ast_result)

        bare_findings = [f for f in findings if f["category"] == "bare_except"]
        assert len(bare_findings) >= 1

    def test_clean_file_no_findings(self, sample_repo: Path):
        """Clean file should produce no findings."""
        from src.agents.code_quality import _analyze_file_locally
        from src.tools.ast_parser import parse_ast_tool

        ast_result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "clean.py"),
        }))

        findings = _analyze_file_locally(str(sample_repo / "clean.py"), ast_result)
        assert len(findings) == 0


class TestCodeQualityNode:
    """Test the full code_quality_node with mocked LLM."""

    @patch("src.agents.code_quality.ChatOllama")
    def test_node_returns_findings(self, mock_ollama, sample_repo: Path, mock_audit_plan):
        """Should return findings for messy files."""
        from src.agents.code_quality import code_quality_node

        # Mock LLM to avoid needing Ollama running
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="LLM analysis placeholder")
        mock_ollama.return_value = mock_llm

        mock_audit_plan["priority_files"] = [
            str(sample_repo / "messy.py"),
            str(sample_repo / "clean.py"),
        ]

        state = {
            "repo_path": str(sample_repo),
            "audit_plan": mock_audit_plan,
        }

        result = code_quality_node(state)

        assert "code_quality_findings" in result
        assert len(result["code_quality_findings"]) > 0
        assert "agent_traces" in result

        # All findings should have the right agent_source
        for f in result["code_quality_findings"]:
            assert f["agent_source"] == "code_quality"
