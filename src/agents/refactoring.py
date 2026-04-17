"""Refactoring agent for CodeSentinel.

Receives combined findings from Code Quality and Security agents,
generates prioritized refactoring plans with concrete before/after
code snippets. Uses deepseek-coder-v2:16b for code generation.
"""

import json
import uuid
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from src.config import LLM_SETTINGS, MODELS, OLLAMA_BASE_URL
from src.db.queries import insert_refactoring_action
from src.observability.tracer import get_tracer
from src.state import AuditState

SYSTEM_PROMPT = """You are the Refactoring Specialist in CodeSentinel, an automated multi-agent code audit system.

## YOUR ROLE
You are an expert code refactoring engineer. You receive combined findings from the Code Quality
and Security agents, then generate concrete, ready-to-apply refactored code with a prioritized
execution plan. Your output must be actionable — developers should be able to copy-paste your
"after" code directly.

## PRIORITIZATION RULES (STRICT ORDER)
1. **Security fixes ALWAYS come first** — SQL injection, command injection, and credential leaks
   must be fixed before any quality improvements.
2. **Critical severity before high, high before medium, etc.** within each category.
3. **Independent fixes before dependent ones** — fixes with no dependencies come first.
4. **Same-file changes grouped together** to minimize merge conflicts.
5. **Quick wins first within same severity** — single-line fixes before multi-function refactors.

## CODE GENERATION RULES
- Generate REAL, syntactically valid code in both before/after fields.
- The "before" field must match the actual vulnerable/problematic code pattern from the finding.
- The "after" field must be a complete, working replacement — not pseudocode.
- Preserve the original code's intent and behavior while fixing the issue.
- Follow the language's idioms and conventions (e.g., parameterized queries for Python DB-API).
- Keep before/after focused on the specific change (3-10 lines), not entire files.

## REFACTORING PATTERNS YOU APPLY
- **SQL Injection → Parameterized Queries**: `f"SELECT...{var}"` → `cursor.execute("SELECT...?", (var,))`
- **Command Injection → Subprocess with list args**: `os.system(f"cmd {var}")` → `subprocess.run(["cmd", var])`
- **Hardcoded Secrets → Environment Variables**: `password = "abc123"` → `password = os.environ["DB_PASSWORD"]`
- **Long Functions → Extract Method**: Split 100+ line functions into focused helpers
- **Deep Nesting → Guard Clauses**: Convert nested if/else to early returns
- **God Classes → Composition**: Split large classes into focused components
- **Bare Except → Specific Exceptions**: `except:` → `except (ValueError, KeyError) as e:`

## OUTPUT FORMAT
Respond with ONLY a JSON array (max 10 items):
[
    {
        "priority": 1,
        "finding_refs": ["SEC-001"],
        "file": "src/database.py",
        "title": "Fix SQL injection with parameterized queries",
        "rationale": "Critical security fix — directly exploitable SQL injection via user input",
        "before": "query = f\"SELECT * FROM users WHERE id = {user_id}\"\\ncursor.execute(query)",
        "after": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
        "changes_summary": "Replace f-string SQL with parameterized query using DB-API placeholders",
        "depends_on": []
    }
]

## WHAT YOU MUST NOT DO
- Do NOT invent code that wasn't referenced in the findings.
- Do NOT generate more than 10 refactoring actions — prioritize ruthlessly.
- Do NOT generate pseudocode or placeholder comments like "// fix here".
- Do NOT change code behavior beyond fixing the identified issue.
- Do NOT produce prose explanations — JSON array only.
- Do NOT skip security findings in favor of quality improvements.
"""


def _build_refactoring_plan_locally(merged_findings: list[dict]) -> list[dict]:
    """Build a deterministic refactoring plan from merged findings.

    Prioritizes security fixes first, then quality improvements,
    sorted by severity within each category.

    Args:
        merged_findings: Combined and deduplicated findings.

    Returns:
        List of refactoring action dicts.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    # Separate security and quality findings
    security = [f for f in merged_findings if f.get("agent_source") == "security"]
    quality = [f for f in merged_findings if f.get("agent_source") == "code_quality"]

    # Sort each by severity
    security.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 3))
    quality.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 3))

    # Build prioritized plan
    plan: list[dict] = []
    priority = 1

    for finding in security + quality:
        if priority > 10:
            break

        plan.append({
            "priority": priority,
            "finding_refs": [finding.get("id", "unknown")],
            "file": finding.get("file", ""),
            "title": f"Fix {finding.get('category', 'issue')} in {Path(finding.get('file', '')).name}",
            "rationale": finding.get("description", ""),
            "before": "",
            "after": "",
            "changes_summary": finding.get("suggestion", f"Address {finding.get('category', 'issue')}"),
            "depends_on": [],
        })
        priority += 1

    return plan


def refactoring_node(state: AuditState) -> dict:
    """Refactoring agent — generate prioritized fix plan from merged findings.

    Reads merged findings, builds a prioritized refactoring plan,
    and optionally uses the LLM to generate before/after code snippets.

    Args:
        state: Current state with merged_findings.

    Returns:
        State update with refactoring_plan and agent_traces.
    """
    tracer = get_tracer()
    tracer.start_agent("refactoring", "Generating refactoring plan")

    try:
        merged = state.get("merged_findings", [])
        run_id = state.get("run_id", 0)

        if not merged:
            trace = tracer.end_agent("refactoring", "No findings to refactor")
            return {
                "refactoring_plan": [],
                "agent_traces": [trace],
            }

        # Step 1: Build deterministic plan
        plan = _build_refactoring_plan_locally(merged)
        tracer.log_tool_call("refactoring", "plan_builder", {}, f"Built plan with {len(plan)} actions")

        # Step 2: Enhance with LLM-generated before/after code
        try:
            model = ChatOllama(
                model=MODELS["refactoring"],
                base_url=OLLAMA_BASE_URL,
                temperature=LLM_SETTINGS["refactoring"]["temperature"],
                num_predict=LLM_SETTINGS["refactoring"]["num_predict"],
            )

            # Send top 5 findings for refactoring suggestions
            top_findings = json.dumps([
                {
                    "id": f.get("id"),
                    "file": f.get("file"),
                    "category": f.get("category"),
                    "description": f.get("description"),
                    "suggestion": f.get("suggestion"),
                }
                for f in merged[:5]
            ], indent=2)

            messages = [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(
                    content=f"Generate refactoring plan with before/after code for these findings:\n{top_findings}"
                ),
            ]

            response = model.invoke(messages)
            tracer.log_llm_call(
                "refactoring",
                MODELS["refactoring"],
                "Generate refactoring plan",
                f"Response: {len(response.content)} chars",
            )

            # Try to parse LLM response and merge with deterministic plan
            try:
                llm_plan = json.loads(response.content)
                if isinstance(llm_plan, list):
                    for i, action in enumerate(llm_plan):
                        if i < len(plan):
                            if action.get("before"):
                                plan[i]["before"] = action["before"]
                            if action.get("after"):
                                plan[i]["after"] = action["after"]
                            if action.get("rationale"):
                                plan[i]["rationale"] = action["rationale"]
            except (json.JSONDecodeError, TypeError):
                tracer.log_error("refactoring", "Could not parse LLM refactoring response — using deterministic plan")

        except Exception as llm_err:
            tracer.log_error("refactoring", f"LLM refactoring failed (non-critical): {llm_err}")

        # Step 3: Persist to database
        if run_id:
            for action in plan:
                try:
                    insert_refactoring_action(run_id, action)
                except Exception:
                    pass  # Non-critical

        # Update final report with refactoring plan
        if state.get("final_report_path"):
            try:
                from src.tools.report_generator import generate_report

                report_result = generate_report.invoke({
                    "repo_name": state.get("audit_plan", {}).get("framework", "repo"),
                    "repo_path": state["repo_path"],
                    "code_quality_findings": json.dumps(state.get("code_quality_findings", [])),
                    "security_findings": json.dumps(state.get("security_findings", [])),
                    "refactoring_plan": json.dumps(plan),
                })
                report_data = json.loads(report_result)
                final_path = report_data.get("data", {}).get("report_path", state.get("final_report_path", ""))
            except Exception:
                final_path = state.get("final_report_path", "")
        else:
            final_path = ""

        trace = tracer.end_agent("refactoring", f"Generated {len(plan)} refactoring actions")

        update: dict = {
            "refactoring_plan": plan,
            "agent_traces": [trace],
        }
        if final_path:
            update["final_report_path"] = final_path

        return update

    except Exception as e:
        trace = tracer.end_agent("refactoring", "", error=str(e))
        return {
            "refactoring_plan": [],
            "agent_traces": [trace],
            "errors": [{"agent": "refactoring", "error": str(e)}],
        }
