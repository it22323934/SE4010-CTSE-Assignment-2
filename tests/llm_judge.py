"""LLM-as-a-Judge evaluation harness for CodeSentinel.

Evaluates agent outputs by scoring them against rubric criteria.
Can use a local Ollama model or operate in deterministic mode
when no LLM is available.
"""

import json
from typing import Any


# --- Evaluation Rubrics ---

RUBRICS: dict[str, dict[str, Any]] = {
    "orchestrator": {
        "name": "Orchestrator Agent Evaluation",
        "criteria": [
            {"id": "plan_completeness", "weight": 0.3, "description": "Does the audit plan include language, framework, priority files, and agent routing?"},
            {"id": "merge_quality", "weight": 0.3, "description": "Are findings properly deduplicated and cross-referenced?"},
            {"id": "report_quality", "weight": 0.2, "description": "Is the final report well-structured with all sections?"},
            {"id": "error_handling", "weight": 0.2, "description": "Does the agent handle missing data gracefully?"},
        ],
    },
    "code_quality": {
        "name": "Code Quality Agent Evaluation",
        "criteria": [
            {"id": "detection_recall", "weight": 0.3, "description": "Does it find all known code smells (long functions, deep nesting, god classes)?"},
            {"id": "severity_accuracy", "weight": 0.2, "description": "Are severity ratings appropriate for each finding?"},
            {"id": "false_positive_rate", "weight": 0.3, "description": "Are there minimal false positives?"},
            {"id": "actionability", "weight": 0.2, "description": "Do findings include useful suggestions?"},
        ],
    },
    "security": {
        "name": "Security Agent Evaluation",
        "criteria": [
            {"id": "vuln_detection", "weight": 0.35, "description": "Does it detect all planted vulnerabilities (secrets, SQLi, command injection)?"},
            {"id": "cwe_accuracy", "weight": 0.2, "description": "Are CWE IDs correctly assigned?"},
            {"id": "severity_accuracy", "weight": 0.2, "description": "Are severity levels appropriate?"},
            {"id": "false_positive_rate", "weight": 0.25, "description": "Minimal false positives on clean code?"},
        ],
    },
    "refactoring": {
        "name": "Refactoring Agent Evaluation",
        "criteria": [
            {"id": "priority_ordering", "weight": 0.3, "description": "Are security fixes prioritized over quality improvements?"},
            {"id": "coverage", "weight": 0.25, "description": "Does the plan address all critical/high findings?"},
            {"id": "code_quality", "weight": 0.25, "description": "Are before/after code suggestions syntactically valid?"},
            {"id": "dependency_ordering", "weight": 0.2, "description": "Are dependencies between actions correctly identified?"},
        ],
    },
}


def evaluate_deterministic(
    agent_name: str,
    findings: list[dict],
    expected_categories: list[str] | None = None,
    expected_min_count: int = 0,
) -> dict:
    """Evaluate agent output using deterministic rules.

    Useful when no LLM is available for judging.

    Args:
        agent_name: Name of the agent being evaluated.
        findings: List of findings produced by the agent.
        expected_categories: Categories that should appear.
        expected_min_count: Minimum expected findings.

    Returns:
        Evaluation result with scores per criterion.
    """
    rubric = RUBRICS.get(agent_name)
    if not rubric:
        return {"error": f"No rubric for agent: {agent_name}"}

    scores: dict[str, float] = {}
    details: dict[str, str] = {}

    # Detection completeness
    if expected_categories:
        found_categories = set(f.get("category", "") for f in findings)
        matched = len(found_categories & set(expected_categories))
        total = len(expected_categories)
        score = matched / total if total > 0 else 0.0
        scores["detection_recall"] = score
        details["detection_recall"] = f"Found {matched}/{total} expected categories"
    else:
        scores["detection_recall"] = 1.0 if len(findings) >= expected_min_count else 0.5

    # Count check
    if len(findings) >= expected_min_count:
        scores["count_met"] = 1.0
        details["count_met"] = f"Found {len(findings)} findings (min: {expected_min_count})"
    else:
        scores["count_met"] = len(findings) / expected_min_count if expected_min_count > 0 else 0.0
        details["count_met"] = f"Found {len(findings)} findings (min: {expected_min_count})"

    # Required fields check
    required_fields = {"id", "file", "severity", "description", "category"}
    valid = sum(1 for f in findings if required_fields.issubset(f.keys()))
    scores["field_completeness"] = valid / len(findings) if findings else 1.0
    details["field_completeness"] = f"{valid}/{len(findings)} findings have all required fields"

    # Severity distribution
    severities = [f.get("severity", "unknown") for f in findings]
    valid_sev = {"critical", "high", "medium", "low"}
    valid_count = sum(1 for s in severities if s in valid_sev)
    scores["severity_validity"] = valid_count / len(severities) if severities else 1.0

    # Weighted overall score
    overall = sum(scores.values()) / len(scores) if scores else 0.0

    return {
        "agent": agent_name,
        "rubric": rubric["name"],
        "findings_count": len(findings),
        "scores": scores,
        "details": details,
        "overall_score": round(overall, 3),
        "pass": overall >= 0.6,
    }


def evaluate_with_llm(
    agent_name: str,
    findings: list[dict],
    model: str = "llama3:8b",
) -> dict:
    """Evaluate agent output using an LLM judge.

    Sends the findings and rubric to a local Ollama model for scoring.
    Falls back to deterministic evaluation if LLM is unavailable.

    Args:
        agent_name: Name of the agent being evaluated.
        findings: List of findings produced by the agent.
        model: Ollama model to use as judge.

    Returns:
        Evaluation result with LLM-generated scores and reasoning.
    """
    rubric = RUBRICS.get(agent_name)
    if not rubric:
        return {"error": f"No rubric for agent: {agent_name}"}

    try:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(model=model, temperature=0.0)

        prompt = f"""You are an expert code audit evaluator. Score the following agent output
against the rubric criteria. Return JSON with scores (0.0-1.0) per criterion.

Agent: {agent_name}
Rubric: {json.dumps(rubric['criteria'], indent=2)}

Findings ({len(findings)} total):
{json.dumps(findings[:10], indent=2)}

Return JSON: {{"scores": {{"criterion_id": score, ...}}, "reasoning": "..."}}"""

        response = llm.invoke(prompt)
        try:
            result = json.loads(response.content)
            result["agent"] = agent_name
            result["method"] = "llm_judge"
            result["model"] = model
            return result
        except json.JSONDecodeError:
            # LLM didn't return valid JSON — fall back
            return evaluate_deterministic(agent_name, findings)

    except Exception:
        # Ollama not available — fall back to deterministic
        return evaluate_deterministic(agent_name, findings)


def run_full_evaluation(pipeline_result: dict) -> dict:
    """Run evaluation across all agents from a pipeline result.

    Args:
        pipeline_result: Final state dict from the LangGraph pipeline.

    Returns:
        Dict with per-agent evaluations and an overall summary.
    """
    evaluations = {}

    # Code Quality
    cq = pipeline_result.get("code_quality_findings", [])
    evaluations["code_quality"] = evaluate_deterministic(
        "code_quality",
        cq,
        expected_categories=["long_function", "deep_nesting", "god_class", "bare_except"],
        expected_min_count=3,
    )

    # Security
    sec = pipeline_result.get("security_findings", [])
    evaluations["security"] = evaluate_deterministic(
        "security",
        sec,
        expected_categories=["hardcoded_secret", "sql_injection", "command_injection"],
        expected_min_count=3,
    )

    # Refactoring
    ref = pipeline_result.get("refactoring_plan", [])
    evaluations["refactoring"] = evaluate_deterministic(
        "refactoring",
        ref,
        expected_min_count=1,
    )

    # Overall
    agent_scores = [e["overall_score"] for e in evaluations.values() if "overall_score" in e]
    overall = sum(agent_scores) / len(agent_scores) if agent_scores else 0.0

    return {
        "evaluations": evaluations,
        "overall_score": round(overall, 3),
        "all_pass": all(e.get("pass", False) for e in evaluations.values()),
    }
