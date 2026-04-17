# Skill: Testing & Evaluation for CodeSentinel

## Testing Strategy Overview

The assignment requires TWO kinds of testing:
1. **Unit tests** for tools (deterministic, standard pytest)
2. **LLM-as-a-Judge evaluation** for agents (non-deterministic, evaluating LLM output quality)

Each student must contribute test cases for their own agent. The group shares a unified test harness.

## Project Testing Structure

```
tests/
├── conftest.py                 # Shared fixtures
├── test_tools.py               # Unit tests for ALL custom tools
├── test_orchestrator.py        # Agent evaluation: Orchestrator
├── test_code_quality.py        # Agent evaluation: Code Quality
├── test_security.py            # Agent evaluation: Security
├── test_refactoring.py         # Agent evaluation: Refactoring
├── test_integration.py         # End-to-end pipeline test
├── llm_judge.py                # Shared LLM-as-a-Judge harness
└── fixtures/
    ├── sample_repo/            # Minimal Git repo with known issues
    │   ├── .git/
    │   ├── vulnerable.py       # Contains known SQL injection, secrets
    │   ├── messy.py            # Contains known code smells
    │   └── clean.py            # No issues (tests for false positives)
    └── expected_outputs/
        ├── expected_cq_findings.json
        └── expected_sec_findings.json
```

## Part 1: Tool Unit Tests (Deterministic)

```python
# tests/conftest.py

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a minimal Git repository with known code issues.

    This repo contains:
    - vulnerable.py: SQL injection, hardcoded secrets, command injection
    - messy.py: Long functions, deep nesting, god class, bare except
    - clean.py: Well-structured code (tests for false positives)

    Returns:
        Path to the temporary Git repository.
    """
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, capture_output=True)

    # vulnerable.py — known security issues
    (repo_dir / "vulnerable.py").write_text('''
import os
import sqlite3
import pickle

API_KEY = "sk-abc123456789secretkey000"
DB_PASSWORD = "admin123!"

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()

def run_command(user_input):
    os.system("echo " + user_input)

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)
''')

    # messy.py — known code quality issues
    (repo_dir / "messy.py").write_text('''
class GodClass:
    """A class that does way too many things."""

    def method_1(self): pass
    def method_2(self): pass
    def method_3(self): pass
    def method_4(self): pass
    def method_5(self): pass
    def method_6(self): pass
    def method_7(self): pass
    def method_8(self): pass
    def method_9(self): pass
    def method_10(self): pass
    def method_11(self): pass

def deeply_nested(data):
    if data:
        for item in data:
            if item.get("active"):
                for sub in item.get("subs", []):
                    if sub.get("valid"):
                        for entry in sub.get("entries", []):
                            if entry:
                                process(entry)

def long_function(a, b, c, d, e, f, g, h, i, j):
    x = a + b
    y = c + d
    z = e + f
''' + "    result = x + y\\n" * 50 + "    return result\\n")

    # clean.py — no issues expected
    (repo_dir / "clean.py").write_text('''
"""Clean module with well-structured code."""

from typing import Optional


def add(a: int, b: int) -> int:
    """Add two integers.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        Sum of a and b.
    """
    return a + b


def greet(name: Optional[str] = None) -> str:
    """Generate a greeting message.

    Args:
        name: Optional name to greet.

    Returns:
        Greeting string.
    """
    if name:
        return f"Hello, {name}!"
    return "Hello, World!"
''')

    # Commit everything
    subprocess.run(["git", "add", "."], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo_dir, capture_output=True)

    return repo_dir


@pytest.fixture
def vulnerable_file(sample_repo: Path) -> Path:
    """Path to the vulnerable.py file in the sample repo."""
    return sample_repo / "vulnerable.py"


@pytest.fixture
def messy_file(sample_repo: Path) -> Path:
    """Path to the messy.py file in the sample repo."""
    return sample_repo / "messy.py"


@pytest.fixture
def clean_file(sample_repo: Path) -> Path:
    """Path to the clean.py file in the sample repo."""
    return sample_repo / "clean.py"
```

### Tool Unit Tests

```python
# tests/test_tools.py

import json
import pytest
from src.tools.ast_parser import parse_ast_tool
from src.tools.pattern_scanner import pattern_scanner
from src.tools.git_analyzer import git_analyzer


class TestASTParsertTool:
    """Unit tests for the AST Parser tool."""

    def test_parses_valid_python_file(self, messy_file):
        """AST parser should extract functions, classes, and metrics from valid Python."""
        result = json.loads(parse_ast_tool.invoke({"file_path": str(messy_file)}))

        assert result["status"] == "success"
        data = result["data"]

        # Should find the GodClass
        class_names = [c["name"] for c in data["classes"]]
        assert "GodClass" in class_names

        # GodClass should have 11+ methods
        god_class = next(c for c in data["classes"] if c["name"] == "GodClass")
        assert god_class["methods_count"] >= 11

        # Should find deeply_nested function
        func_names = [f["name"] for f in data["functions"]]
        assert "deeply_nested" in func_names

        # deeply_nested should have high nesting depth
        nested_func = next(f for f in data["functions"] if f["name"] == "deeply_nested")
        assert nested_func["max_nesting_depth"] >= 4

        # long_function should have high line count
        long_func = next(f for f in data["functions"] if f["name"] == "long_function")
        assert long_func["line_count"] > 50

    def test_handles_nonexistent_file(self):
        """AST parser should return error for missing files, not crash."""
        result = json.loads(parse_ast_tool.invoke({"file_path": "/does/not/exist.py"}))
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    def test_handles_non_python_file(self, sample_repo):
        """AST parser should reject non-Python files."""
        readme = sample_repo / "README.md"
        readme.write_text("# Test")
        result = json.loads(parse_ast_tool.invoke({"file_path": str(readme)}))
        assert result["status"] == "error"

    def test_clean_file_has_type_hints(self, clean_file):
        """Clean file's functions should show return type annotations."""
        result = json.loads(parse_ast_tool.invoke({"file_path": str(clean_file)}))
        data = result["data"]

        for func in data["functions"]:
            assert func["returns"] is not None, f"Function {func['name']} missing return type"
            assert func["has_docstring"] is True, f"Function {func['name']} missing docstring"


class TestPatternScanner:
    """Unit tests for the Pattern Scanner tool."""

    def test_detects_hardcoded_secrets(self, vulnerable_file):
        """Scanner should find API_KEY and DB_PASSWORD."""
        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vulnerable_file),
            "scan_type": "all"
        }))

        assert result["status"] == "success"
        categories = [f["category"] for f in result["data"]["matches"]]
        assert "hardcoded_secret" in categories

    def test_detects_sql_injection(self, vulnerable_file):
        """Scanner should find f-string SQL injection in get_user."""
        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vulnerable_file),
            "scan_type": "all"
        }))

        categories = [f["category"] for f in result["data"]["matches"]]
        assert "sql_injection" in categories

    def test_detects_command_injection(self, vulnerable_file):
        """Scanner should find os.system with concatenation."""
        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vulnerable_file),
            "scan_type": "all"
        }))

        categories = [f["category"] for f in result["data"]["matches"]]
        assert "command_injection" in categories

    def test_no_false_positives_on_clean_file(self, clean_file):
        """Scanner should NOT flag clean.py — zero findings expected."""
        result = json.loads(pattern_scanner.invoke({
            "file_path": str(clean_file),
            "scan_type": "all"
        }))

        assert result["status"] == "success"
        assert len(result["data"]["matches"]) == 0


class TestGitAnalyzer:
    """Unit tests for the Git Analyzer tool."""

    def test_gets_repo_info(self, sample_repo):
        """Git analyzer should return repo metadata."""
        result = json.loads(git_analyzer.invoke({
            "repo_path": str(sample_repo),
            "operation": "repo_info"
        }))

        assert result["status"] == "success"
        assert result["data"]["file_count"] >= 3

    def test_gets_recent_changes(self, sample_repo):
        """Git analyzer should return recently changed files."""
        result = json.loads(git_analyzer.invoke({
            "repo_path": str(sample_repo),
            "operation": "recent_changes",
            "params": {"n_commits": 5}
        }))

        assert result["status"] == "success"
        assert len(result["data"]["changed_files"]) >= 1
```

---

## Part 2: LLM-as-a-Judge Evaluation (Agent Output Quality)

This is the more important part for the assignment. Each student must validate that their agent produces accurate, well-structured, non-hallucinated output.

```python
# tests/llm_judge.py

"""LLM-as-a-Judge evaluation harness for CodeSentinel agents.

Uses a separate Ollama model to evaluate agent outputs for:
- Accuracy: Are the findings real or hallucinated?
- Completeness: Did the agent catch all known issues?
- Format compliance: Is the output valid JSON matching the expected schema?
- Safety: Does the agent avoid fabricating file paths or line numbers?
"""

import json
from typing import Any
from dataclasses import dataclass

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from src.config import MODELS


JUDGE_SYSTEM_PROMPT = """You are an evaluation judge for a code audit system.
You will be given:
1. The EXPECTED findings for a test file (ground truth)
2. The ACTUAL findings produced by an agent
3. The SOURCE FILE content

Your job is to evaluate the agent's output on these criteria:

## CRITERIA
1. ACCURACY (0-10): Are the findings real? Do the file paths and line numbers exist?
   Deduct points for hallucinated findings (claiming issues that don't exist).

2. COMPLETENESS (0-10): Did the agent find all the known issues?
   Deduct points for each missed known issue.

3. FORMAT_COMPLIANCE (0-10): Is the output valid JSON matching the expected schema?
   Each finding must have: file, line_start, line_end, category, severity, description.

4. NO_HALLUCINATION (0-10): Did the agent invent any files, functions, or line numbers
   that don't exist in the source? Score 0 if any hallucination is detected.

## OUTPUT FORMAT
Respond ONLY with JSON:
{
    "accuracy": 8,
    "completeness": 7,
    "format_compliance": 10,
    "no_hallucination": 10,
    "overall_score": 8.75,
    "reasoning": "Found 3/4 known issues. Missed the pickle deserialization vulnerability...",
    "hallucinations_detected": [],
    "missed_findings": ["insecure_deserialization in line 14"]
}
"""


@dataclass
class JudgeResult:
    """Result of an LLM-as-a-Judge evaluation."""
    accuracy: float
    completeness: float
    format_compliance: float
    no_hallucination: float
    overall_score: float
    reasoning: str
    hallucinations_detected: list[str]
    missed_findings: list[str]


class LLMJudge:
    """Evaluates agent outputs using an LLM-as-a-Judge approach.

    Uses a separate LLM instance (can be same model, different temperature)
    to objectively score agent outputs against ground truth.
    """

    def __init__(self, model_name: str = "llama3:8b"):
        """Initialize the judge with a specified model.

        Args:
            model_name: Ollama model to use for judging.
        """
        self.model = ChatOllama(
            model=model_name,
            temperature=0.0,  # Deterministic judging
            format="json",
        )

    def evaluate(
        self,
        agent_output: list[dict],
        expected_findings: list[dict],
        source_content: str,
        agent_name: str
    ) -> JudgeResult:
        """Evaluate an agent's output against ground truth.

        Args:
            agent_output: The actual findings produced by the agent.
            expected_findings: Known correct findings (ground truth).
            source_content: The original source file content.
            agent_name: Name of the agent being evaluated.

        Returns:
            JudgeResult with scores and detailed reasoning.
        """
        evaluation_prompt = f"""
## AGENT BEING EVALUATED: {agent_name}

## EXPECTED FINDINGS (GROUND TRUTH):
{json.dumps(expected_findings, indent=2)}

## ACTUAL AGENT OUTPUT:
{json.dumps(agent_output, indent=2)}

## SOURCE FILE CONTENT:
```
{source_content}
```

Evaluate the agent's output and provide your scores.
"""

        messages = [
            SystemMessage(content=JUDGE_SYSTEM_PROMPT),
            HumanMessage(content=evaluation_prompt)
        ]

        response = self.model.invoke(messages)

        try:
            result_data = json.loads(response.content)
            return JudgeResult(**result_data)
        except (json.JSONDecodeError, TypeError) as e:
            return JudgeResult(
                accuracy=0, completeness=0, format_compliance=0,
                no_hallucination=0, overall_score=0,
                reasoning=f"Judge failed to produce valid JSON: {e}",
                hallucinations_detected=[], missed_findings=[]
            )

    def evaluate_multiple(
        self,
        results: list[tuple[list[dict], list[dict], str]],
        agent_name: str,
        min_passing_score: float = 6.0
    ) -> dict[str, Any]:
        """Evaluate multiple test cases and aggregate results.

        Args:
            results: List of (agent_output, expected, source_content) tuples.
            agent_name: Name of the agent.
            min_passing_score: Minimum average score to pass.

        Returns:
            Aggregated evaluation summary.
        """
        evaluations = []
        for agent_output, expected, source in results:
            eval_result = self.evaluate(agent_output, expected, source, agent_name)
            evaluations.append(eval_result)

        avg_score = sum(e.overall_score for e in evaluations) / len(evaluations)

        return {
            "agent": agent_name,
            "test_cases": len(evaluations),
            "average_score": round(avg_score, 2),
            "passed": avg_score >= min_passing_score,
            "individual_scores": [
                {
                    "accuracy": e.accuracy,
                    "completeness": e.completeness,
                    "format_compliance": e.format_compliance,
                    "no_hallucination": e.no_hallucination,
                    "overall": e.overall_score,
                    "reasoning": e.reasoning
                }
                for e in evaluations
            ],
            "total_hallucinations": sum(len(e.hallucinations_detected) for e in evaluations),
            "total_missed": sum(len(e.missed_findings) for e in evaluations),
        }
```

### Per-Agent Evaluation Tests

```python
# tests/test_security.py (Student 3's responsibility)

import json
import pytest
from src.agents.security import security_node
from src.state import AuditState
from tests.llm_judge import LLMJudge


# Ground truth: what the security agent SHOULD find in vulnerable.py
EXPECTED_SECURITY_FINDINGS = [
    {
        "category": "hardcoded_secret",
        "severity": "critical",
        "description_contains": "API_KEY",
    },
    {
        "category": "hardcoded_secret",
        "severity": "critical",
        "description_contains": "DB_PASSWORD",
    },
    {
        "category": "sql_injection",
        "severity": "critical",
        "description_contains": "f-string",
    },
    {
        "category": "command_injection",
        "severity": "critical",
        "description_contains": "os.system",
    },
    {
        "category": "insecure_deserialization",
        "severity": "high",
        "description_contains": "pickle",
    },
]


class TestSecurityAgent:
    """Evaluation tests for the Security Vulnerability Agent."""

    @pytest.fixture
    def judge(self):
        return LLMJudge(model_name="llama3:8b")

    def test_detects_all_vulnerabilities(self, sample_repo, judge):
        """Security agent should detect all 5 known vulnerabilities in vulnerable.py."""
        # Build minimal state
        state: AuditState = {
            "repo_path": str(sample_repo),
            "run_id": 1,
            "audit_plan": {
                "language": "python",
                "framework": "none",
                "priority_files": [str(sample_repo / "vulnerable.py")],
                "total_files": 1,
                "run_code_quality": False,
                "run_security": True,
                "previous_audit_exists": False,
                "previous_run_id": None,
                "prioritization_reason": "test",
                "notes": "",
            },
        }

        # Run agent
        result = security_node(state)
        findings = result.get("security_findings", [])

        # Structural assertions
        assert len(findings) >= 4, f"Expected at least 4 findings, got {len(findings)}"

        categories = [f["category"] for f in findings]
        assert "hardcoded_secret" in categories, "Missed hardcoded secrets"
        assert "sql_injection" in categories, "Missed SQL injection"
        assert "command_injection" in categories, "Missed command injection"

        # LLM-as-a-Judge evaluation
        source = (sample_repo / "vulnerable.py").read_text()
        judge_result = judge.evaluate(findings, EXPECTED_SECURITY_FINDINGS, source, "security")

        assert judge_result.no_hallucination >= 7, \
            f"Hallucination detected: {judge_result.hallucinations_detected}"
        assert judge_result.overall_score >= 6.0, \
            f"Agent scored below threshold: {judge_result.reasoning}"

    def test_no_false_positives_on_clean_file(self, sample_repo):
        """Security agent should return zero findings for clean.py."""
        state: AuditState = {
            "repo_path": str(sample_repo),
            "run_id": 1,
            "audit_plan": {
                "language": "python",
                "framework": "none",
                "priority_files": [str(sample_repo / "clean.py")],
                "total_files": 1,
                "run_code_quality": False,
                "run_security": True,
                "previous_audit_exists": False,
                "previous_run_id": None,
                "prioritization_reason": "test",
                "notes": "",
            },
        }

        result = security_node(state)
        findings = result.get("security_findings", [])

        assert len(findings) == 0, \
            f"False positives detected on clean file: {[f['category'] for f in findings]}"

    def test_output_format_compliance(self, sample_repo):
        """Every finding must have all required fields with correct types."""
        state: AuditState = {
            "repo_path": str(sample_repo),
            "run_id": 1,
            "audit_plan": {
                "language": "python",
                "framework": "none",
                "priority_files": [str(sample_repo / "vulnerable.py")],
                "total_files": 1,
                "run_code_quality": False,
                "run_security": True,
                "previous_audit_exists": False,
                "previous_run_id": None,
                "prioritization_reason": "test",
                "notes": "",
            },
        }

        result = security_node(state)
        findings = result.get("security_findings", [])

        required_fields = {"file", "line_start", "category", "severity", "description"}
        valid_severities = {"critical", "high", "medium", "low"}

        for finding in findings:
            for field in required_fields:
                assert field in finding, f"Missing required field: {field}"
            assert finding["severity"] in valid_severities, \
                f"Invalid severity: {finding['severity']}"
            assert isinstance(finding["line_start"], int), \
                f"line_start must be int, got {type(finding['line_start'])}"
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run only tool unit tests (fast, deterministic)
pytest tests/test_tools.py -v

# Run a specific agent's evaluation (requires Ollama running)
pytest tests/test_security.py -v --timeout=120

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run integration test (full pipeline, slow)
pytest tests/test_integration.py -v --timeout=300
```