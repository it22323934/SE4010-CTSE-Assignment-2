"""FastAPI backend for the CodeSentinel web UI.

Provides REST API endpoints for:
- Starting audit runs
- Streaming pipeline progress via SSE
- Querying findings and reports
- Historical audit comparisons
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.config import DB_PATH, REPORTS_DIR
from src.db.queries import (
    get_findings_for_run,
    get_previous_runs,
    init_db,
)
from src.graph import build_graph
from src.observability.tracer import get_tracer, init_tracer

app = FastAPI(
    title="CodeSentinel API",
    description="Intelligent Codebase Audit & Refactoring MAS",
    version="1.0.0",
)

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Active audit tracking ---
_active_audits: dict[str, dict[str, Any]] = {}


class AuditRequest(BaseModel):
    """Request body for starting a new audit."""

    repo_path: str | None = Field(default=None, description="Absolute path to a local Git repository")
    repo_url: str | None = Field(default=None, description="Remote Git URL to clone and audit")
    branch: str | None = Field(default=None, description="Branch to checkout when cloning")


class AuditStatusResponse(BaseModel):
    """Response for audit status queries."""

    run_id: int
    status: str
    current_step: str | None = None
    steps_completed: int = 0
    total_steps: int = 5
    findings_count: int = 0
    errors: list[dict] = []


@app.on_event("startup")
async def startup() -> None:
    """Initialize database on server startup."""
    init_db()


@app.post("/api/audit/start")
async def start_audit(request: AuditRequest) -> dict:
    """Start a new audit pipeline for a repository.

    Accepts either a local repo_path OR a remote repo_url.
    If repo_url is given, the repo is cloned into data/cloned_repos/ first.

    Args:
        request: Audit request with repo_path or repo_url.

    Returns:
        Dict with audit_id and initial status.

    Raises:
        HTTPException: If repo path/url is invalid.
    """
    if request.repo_url:
        # Clone the remote repository first
        from src.tools.repo_cloner import clone_repository
        result = json.loads(clone_repository.invoke({
            "repo_url": request.repo_url,
            "branch": request.branch,
        }))
        if result["status"] != "success":
            raise HTTPException(status_code=400, detail=f"Clone failed: {result.get('error', 'Unknown')}")
        repo_path = Path(result["local_path"]).resolve()
    elif request.repo_path:
        repo_path = Path(request.repo_path).resolve()
    else:
        raise HTTPException(status_code=400, detail="Provide either repo_path or repo_url")

    if not repo_path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {repo_path}")
    if not (repo_path / ".git").exists():
        raise HTTPException(status_code=400, detail=f"Not a Git repository: {repo_path}")

    audit_id = f"audit-{int(time.time())}"

    # Track the audit
    _active_audits[audit_id] = {
        "status": "starting",
        "repo_path": str(repo_path),
        "repo_url": request.repo_url,
        "start_time": datetime.now().isoformat(),
        "current_step": "orchestrator_plan",
        "steps": {},
        "result": None,
        "error": None,
    }

    # Run audit in background
    asyncio.create_task(_run_audit_async(audit_id, str(repo_path)))

    return {"audit_id": audit_id, "status": "starting", "repo_path": str(repo_path)}


async def _run_audit_async(audit_id: str, repo_path: str) -> None:
    """Run the audit pipeline asynchronously.

    Args:
        audit_id: Unique audit identifier.
        repo_path: Path to the repository.
    """
    audit = _active_audits[audit_id]

    try:
        init_db()
        tracer = init_tracer(run_id=0)
        graph = build_graph()

        initial_state = {
            "repo_path": repo_path,
            "run_id": 0,
            "code_quality_findings": [],
            "security_findings": [],
            "agent_traces": [],
            "errors": [],
        }

        # Step tracking
        step_names = ["orchestrator_plan", "code_quality", "security", "merge_findings", "refactoring"]

        # Run the graph
        audit["status"] = "running"
        result = await asyncio.to_thread(graph.invoke, initial_state)

        audit["status"] = "completed"
        audit["result"] = {
            "run_id": result.get("run_id", 0),
            "code_quality_findings": result.get("code_quality_findings", []),
            "security_findings": result.get("security_findings", []),
            "merged_findings": result.get("merged_findings", []),
            "refactoring_plan": result.get("refactoring_plan", []),
            "final_report_path": result.get("final_report_path", ""),
            "errors": result.get("errors", []),
            "agent_traces": result.get("agent_traces", []),
        }

        # Mark all steps as completed
        for step in step_names:
            audit["steps"][step] = "completed"
        audit["current_step"] = None

        tracer.save()

    except Exception as e:
        audit["status"] = "failed"
        audit["error"] = str(e)


@app.get("/api/audit/{audit_id}/status")
async def get_audit_status(audit_id: str) -> dict:
    """Get the current status of an audit.

    Args:
        audit_id: The audit identifier.

    Returns:
        Current status, step info, and partial results.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail="Audit not found")

    audit = _active_audits[audit_id]

    response = {
        "audit_id": audit_id,
        "status": audit["status"],
        "current_step": audit.get("current_step"),
        "steps": audit.get("steps", {}),
        "start_time": audit.get("start_time"),
        "error": audit.get("error"),
    }

    if audit["status"] == "completed" and audit.get("result"):
        result = audit["result"]
        response["findings"] = {
            "code_quality": result.get("code_quality_findings", []),
            "security": result.get("security_findings", []),
            "merged": result.get("merged_findings", []),
            "refactoring": result.get("refactoring_plan", []),
        }
        response["report_path"] = result.get("final_report_path", "")
        response["run_id"] = result.get("run_id", 0)

    return response


@app.get("/api/audit/{audit_id}/stream")
async def stream_audit_progress(audit_id: str) -> StreamingResponse:
    """Stream audit progress via Server-Sent Events (SSE).

    Args:
        audit_id: The audit identifier.

    Returns:
        SSE stream with progress updates.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail="Audit not found")

    async def event_generator():
        step_names = ["orchestrator_plan", "code_quality", "security", "merge_findings", "refactoring"]
        last_status = ""

        while True:
            audit = _active_audits.get(audit_id, {})
            current_status = audit.get("status", "unknown")

            if current_status != last_status:
                data = json.dumps({
                    "status": current_status,
                    "current_step": audit.get("current_step"),
                    "steps": audit.get("steps", {}),
                })
                yield f"data: {data}\n\n"
                last_status = current_status

            if current_status in ("completed", "failed"):
                # Send final result
                if audit.get("result"):
                    result = audit["result"]
                    final_data = json.dumps({
                        "status": current_status,
                        "findings": {
                            "code_quality": result.get("code_quality_findings", []),
                            "security": result.get("security_findings", []),
                            "refactoring": result.get("refactoring_plan", []),
                        },
                        "report_path": result.get("final_report_path", ""),
                    })
                    yield f"data: {final_data}\n\n"
                break

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@app.get("/api/history")
async def get_audit_history(repo_path: str | None = None) -> dict:
    """Get historical audit runs, optionally filtered by repo.

    Args:
        repo_path: Optional repository path to filter by.

    Returns:
        List of previous audit runs.
    """
    if repo_path:
        runs = get_previous_runs(repo_path)
    else:
        # Get all runs
        import sqlite3
        from src.config import DB_PATH

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM audit_runs ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
        conn.close()
        runs = [dict(row) for row in rows]

    return {"runs": runs}


@app.get("/api/findings/{run_id}")
async def get_findings(run_id: int) -> dict:
    """Get all findings for a specific audit run.

    Args:
        run_id: The audit run ID.

    Returns:
        Dict with findings list.
    """
    findings = get_findings_for_run(run_id)
    return {"findings": findings, "count": len(findings)}


@app.get("/api/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "database": str(DB_PATH),
    }
