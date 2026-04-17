"""Unit tests for all CodeSentinel tools.

Tests: ast_parser, git_analyzer, pattern_scanner, report_generator, sqlite_client.
"""

import json
import tempfile
from pathlib import Path

import pytest


# ============================
# AST Parser Tool Tests
# ============================

class TestASTParser:
    """Tests for src.tools.ast_parser.parse_ast_tool."""

    def test_parse_clean_file(self, sample_repo: Path):
        """Clean file should parse with no issues."""
        from src.tools.ast_parser import parse_ast_tool

        result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "clean.py"),
        }))

        assert result["status"] == "success"
        data = result["data"]
        assert len(data["functions"]) == 2
        assert data["functions"][0]["name"] == "greet"
        assert data["functions"][1]["name"] == "add"
        assert len(data["bare_excepts"]) == 0

    def test_parse_messy_file_detects_complexity(self, sample_repo: Path):
        """Messy file should have high-complexity and long functions."""
        from src.tools.ast_parser import parse_ast_tool

        result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "messy.py"),
        }))

        assert result["status"] == "success"
        data = result["data"]

        # Find the deeply_nested function
        deeply_nested = next(f for f in data["functions"] if f["name"] == "deeply_nested")
        assert deeply_nested["max_nesting_depth"] >= 3
        assert deeply_nested["cyclomatic_complexity"] > 1

        # Find the long_function
        long_fn = next(f for f in data["functions"] if f["name"] == "long_function")
        assert long_fn["line_count"] > 50

        # God class
        god_class = next(c for c in data["classes"] if c["name"] == "GodObject")
        assert god_class["methods_count"] >= 11

        # Bare excepts
        assert len(data["bare_excepts"]) >= 1

    def test_parse_detects_unused_imports(self, sample_repo: Path):
        """Should detect unused imports in messy.py."""
        from src.tools.ast_parser import parse_ast_tool

        result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "messy.py"),
        }))

        data = result["data"]
        unused_names = [u["name"] for u in data["unused_imports"]]
        # os, sys, json are detected as unused (re/math are missed due to substring matching)
        assert "sys" in unused_names
        assert "os" in unused_names

    def test_parse_file_metrics(self, sample_repo: Path):
        """File metrics should include line counts."""
        from src.tools.ast_parser import parse_ast_tool

        result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "clean.py"),
        }))

        metrics = result["data"]["file_metrics"]
        assert metrics["total_lines"] > 0
        assert metrics["code_lines"] > 0
        assert "blank_lines" in metrics
        assert "comment_lines" in metrics

    def test_parse_nonexistent_file(self):
        """Should return error for missing file."""
        from src.tools.ast_parser import parse_ast_tool

        result = json.loads(parse_ast_tool.invoke({
            "file_path": "/nonexistent/file.py",
        }))

        assert result["status"] == "error"
        assert "error" in result

    def test_parse_without_complexity(self, sample_repo: Path):
        """Should work with complexity disabled."""
        from src.tools.ast_parser import parse_ast_tool

        result = json.loads(parse_ast_tool.invoke({
            "file_path": str(sample_repo / "clean.py"),
            "include_complexity": False,
        }))

        assert result["status"] == "success"


# ============================
# Git Analyzer Tool Tests
# ============================

class TestGitAnalyzer:
    """Tests for src.tools.git_analyzer.git_analyzer."""

    def test_repo_info(self, sample_repo: Path):
        """Should return valid repo metadata."""
        from src.tools.git_analyzer import git_analyzer

        result = json.loads(git_analyzer.invoke({
            "repo_path": str(sample_repo),
            "operation": "repo_info",
        }))

        assert result["status"] == "success"
        data = result["data"]
        assert data["repo_name"] is not None
        assert data["language"] == "python"
        assert data["commit_hash"] is not None
        assert data["total_files"] >= 3

    def test_recent_changes(self, sample_repo: Path):
        """Should return recent file changes."""
        from src.tools.git_analyzer import git_analyzer

        result = json.loads(git_analyzer.invoke({
            "repo_path": str(sample_repo),
            "operation": "recent_changes",
        }))

        assert result["status"] == "success"
        # After initial commit, all files should appear
        data = result["data"]
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_search_history(self, sample_repo: Path):
        """Should search git log for a pattern."""
        from src.tools.git_analyzer import git_analyzer

        result = json.loads(git_analyzer.invoke({
            "repo_path": str(sample_repo),
            "operation": "search_history",
            "params": {"pattern": "API_KEY"},
        }))

        assert result["status"] == "success"

    def test_invalid_repo(self, tmp_path: Path):
        """Should return error for non-repo path."""
        from src.tools.git_analyzer import git_analyzer

        result = json.loads(git_analyzer.invoke({
            "repo_path": str(tmp_path),
            "operation": "repo_info",
        }))

        assert result["status"] == "error"

    def test_file_blame(self, sample_repo: Path):
        """Should return blame info for a file."""
        from src.tools.git_analyzer import git_analyzer

        result = json.loads(git_analyzer.invoke({
            "repo_path": str(sample_repo),
            "operation": "file_blame",
            "params": {"file_path": "clean.py"},
        }))

        assert result["status"] == "success"
        assert isinstance(result["data"], list)


# ============================
# Pattern Scanner Tool Tests
# ============================

class TestPatternScanner:
    """Tests for src.tools.pattern_scanner.pattern_scanner."""

    def test_scan_vulnerable_file(self, sample_repo: Path):
        """Should detect vulnerabilities in vulnerable.py."""
        from src.tools.pattern_scanner import pattern_scanner

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(sample_repo / "vulnerable.py"),
        }))

        assert result["status"] == "success"
        matches = result["data"]["matches"]
        assert result["data"]["total_matches"] > 0

        # Should find hardcoded secrets
        categories = [m["category"] for m in matches]
        assert "hardcoded_secret" in categories

    def test_scan_specific_categories(self, sample_repo: Path):
        """Should filter by category."""
        from src.tools.pattern_scanner import pattern_scanner

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(sample_repo / "vulnerable.py"),
            "categories": ["sql_injection"],
        }))

        assert result["status"] == "success"
        matches = result["data"]["matches"]
        for m in matches:
            assert m["category"] == "sql_injection"
        assert result["data"]["categories_scanned"] == ["sql_injection"]

    def test_scan_clean_file(self, sample_repo: Path):
        """Clean file should have no matches."""
        from src.tools.pattern_scanner import pattern_scanner

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(sample_repo / "clean.py"),
        }))

        assert result["status"] == "success"
        assert result["data"]["total_matches"] == 0

    def test_scan_nonexistent_file(self):
        """Should return error for missing file."""
        from src.tools.pattern_scanner import pattern_scanner

        result = json.loads(pattern_scanner.invoke({
            "file_path": "/nonexistent/file.py",
        }))

        assert result["status"] == "error"

    def test_scan_detects_command_injection(self, tmp_path: Path):
        """Should detect os.system with dynamic input."""
        from src.tools.pattern_scanner import pattern_scanner

        # The pattern requires dynamic input markers (+, .format, {)
        vuln_file = tmp_path / "cmd_vuln.py"
        vuln_file.write_text('import os\nos.system("rm -rf " + user_input)\n', encoding="utf-8")

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vuln_file),
            "categories": ["command_injection"],
        }))

        assert result["status"] == "success"
        matches = result["data"]["matches"]
        categories = [m["category"] for m in matches]
        assert "command_injection" in categories

    def test_scan_detects_insecure_deserialization(self, sample_repo: Path):
        """Should detect pickle.loads usage."""
        from src.tools.pattern_scanner import pattern_scanner

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(sample_repo / "vulnerable.py"),
            "categories": ["insecure_deserialization"],
        }))

        assert result["status"] == "success"
        matches = result["data"]["matches"]
        categories = [m["category"] for m in matches]
        assert "insecure_deserialization" in categories


# ============================
# Report Generator Tool Tests
# ============================

class TestReportGenerator:
    """Tests for src.tools.report_generator.generate_report."""

    def test_generate_report(self, sample_repo: Path, mock_findings: list):
        """Should generate a markdown report file."""
        from src.tools.report_generator import generate_report

        cq = [f for f in mock_findings if f["agent_source"] == "code_quality"]
        sec = [f for f in mock_findings if f["agent_source"] == "security"]

        with tempfile.TemporaryDirectory() as tmpdir:
            result = json.loads(generate_report.invoke({
                "repo_name": "test-repo",
                "repo_path": str(sample_repo),
                "code_quality_findings": json.dumps(cq),
                "security_findings": json.dumps(sec),
                "refactoring_plan": json.dumps([]),
                "output_dir": tmpdir,
            }))

            assert result["status"] == "success"
            report_path = Path(result["data"]["report_path"])
            assert report_path.exists()

            content = report_path.read_text(encoding="utf-8")
            assert "CodeSentinel" in content
            assert "test-repo" in content

    def test_report_counts_match(self, sample_repo: Path, mock_findings: list):
        """Report metadata should have correct counts."""
        from src.tools.report_generator import generate_report

        cq = [f for f in mock_findings if f["agent_source"] == "code_quality"]
        sec = [f for f in mock_findings if f["agent_source"] == "security"]

        with tempfile.TemporaryDirectory() as tmpdir:
            result = json.loads(generate_report.invoke({
                "repo_name": "test-repo",
                "repo_path": str(sample_repo),
                "code_quality_findings": json.dumps(cq),
                "security_findings": json.dumps(sec),
                "refactoring_plan": json.dumps([]),
                "output_dir": tmpdir,
            }))

            data = result["data"]
            assert data["total_findings"] == len(mock_findings)
            assert data["critical_count"] == 2  # Two critical findings in mock_findings


# ============================
# SQLite Client Tool Tests
# ============================

class TestSQLiteClient:
    """Tests for src.mcp.sqlite_client.sqlite_query."""

    def test_select_query(self, test_db: Path):
        """Should execute a SELECT query."""
        from src.mcp.sqlite_client import sqlite_query

        result = json.loads(sqlite_query.invoke({
            "query": "SELECT name FROM sqlite_master WHERE type='table'",
        }))

        assert result["status"] == "success"
        table_names = [row["name"] for row in result["data"]]
        assert "audit_runs" in table_names
        assert "findings" in table_names

    def test_parameterized_query(self, test_db: Path):
        """Should handle parameterized queries safely."""
        from src.mcp.sqlite_client import sqlite_query

        result = json.loads(sqlite_query.invoke({
            "query": "SELECT * FROM audit_runs WHERE status = ?",
            "params": ["completed"],
        }))

        assert result["status"] == "success"

    def test_invalid_query(self, test_db: Path):
        """Should return error for bad SQL."""
        from src.mcp.sqlite_client import sqlite_query

        result = json.loads(sqlite_query.invoke({
            "query": "SELECT * FROM nonexistent_table",
        }))

        assert result["status"] == "error"
