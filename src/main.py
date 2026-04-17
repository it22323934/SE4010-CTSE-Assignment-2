"""CodeSentinel CLI entry point.

Usage:
    python -m src.main --repo /path/to/target/repo
    python -m src.main --url https://github.com/owner/repo
    python -m src.main --repo /path/to/target/repo --api  (start FastAPI server)
"""

import argparse
import json
import sys
from pathlib import Path

from src.config import DB_PATH
from src.db.queries import init_db, update_audit_run_status
from src.graph import build_graph
from src.observability.tracer import get_tracer, init_tracer


def resolve_repo_path(repo: str | None, url: str | None, branch: str | None = None) -> str:
    """Resolve a repository path from either a local path or remote URL.

    If --url is given, clones the repo into data/cloned_repos/ and returns
    the local path. If --repo is given, validates and returns it directly.

    Args:
        repo: Local filesystem path to a Git repo.
        url: Remote Git URL to clone.
        branch: Optional branch to checkout when cloning.

    Returns:
        Absolute path to the local Git repository.

    Raises:
        ValueError: If neither repo nor url is provided, or if cloning fails.
    """
    if url:
        from src.tools.repo_cloner import clone_repository
        print(f"📥 Cloning repository: {url}")
        result = json.loads(clone_repository.invoke({
            "repo_url": url,
            "branch": branch,
        }))
        if result["status"] != "success":
            raise ValueError(f"Clone failed: {result.get('error', 'Unknown error')}")
        local_path = result["local_path"]
        print(f"   ✅ {result['action'].capitalize()}: {local_path}")
        return local_path
    elif repo:
        return repo
    else:
        raise ValueError("Provide either --repo (local path) or --url (remote Git URL)")


def run_audit(repo_path: str) -> dict:
    """Execute a full CodeSentinel audit on a repository.

    Args:
        repo_path: Absolute path to the Git repository to audit.

    Returns:
        Final audit state dictionary with all findings and report path.

    Raises:
        FileNotFoundError: If the repository path does not exist.
        ValueError: If the path is not a Git repository.
    """
    path = Path(repo_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
    if not (path / ".git").exists():
        raise ValueError(f"Not a Git repository (no .git directory): {repo_path}")

    # Initialize database
    init_db()

    # Initialize tracer with temp run_id (will be updated by orchestrator)
    tracer = init_tracer(run_id=0)

    # Build and run the graph
    graph = build_graph()

    initial_state = {
        "repo_path": str(path),
        "run_id": 0,
        "code_quality_findings": [],
        "security_findings": [],
        "agent_traces": [],
        "errors": [],
    }

    print(f"\n🛡️  CodeSentinel Audit Starting...")
    print(f"📁 Repository: {path}")
    print(f"{'─' * 60}")

    # Run the pipeline
    final_state = graph.invoke(initial_state)

    # Update run status
    run_id = final_state.get("run_id", 0)
    if run_id:
        errors = final_state.get("errors", [])
        status = "failed" if errors else "completed"
        update_audit_run_status(run_id, status)

    # Save trace
    tracer.save()

    # Print summary
    cq = final_state.get("code_quality_findings", [])
    sec = final_state.get("security_findings", [])
    merged = final_state.get("merged_findings", [])
    refactoring = final_state.get("refactoring_plan", [])
    report = final_state.get("final_report_path", "")

    print(f"\n{'─' * 60}")
    print(f"✅ Audit Complete!")
    print(f"   Code Quality Findings: {len(cq)}")
    print(f"   Security Findings:     {len(sec)}")
    print(f"   Merged (deduplicated): {len(merged)}")
    print(f"   Refactoring Actions:   {len(refactoring)}")
    if report:
        print(f"   Report: {report}")

    errors = final_state.get("errors", [])
    if errors:
        print(f"\n⚠️  Errors encountered:")
        for err in errors:
            print(f"   - [{err.get('agent', '?')}] {err.get('error', 'unknown')}")

    return final_state


def main() -> None:
    """CLI entry point for CodeSentinel."""
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="CodeSentinel — Intelligent Codebase Audit & Refactoring MAS",
    )
    repo_group = parser.add_mutually_exclusive_group(required=True)
    repo_group.add_argument(
        "--repo",
        type=str,
        help="Absolute path to a local Git repository to audit",
    )
    repo_group.add_argument(
        "--url",
        type=str,
        help="Remote Git URL to clone and audit (e.g. https://github.com/owner/repo)",
    )
    parser.add_argument(
        "--branch",
        type=str,
        default=None,
        help="Branch to checkout when cloning a remote repo (default: repo's default branch)",
    )
    parser.add_argument(
        "--api",
        action="store_true",
        help="Start the FastAPI server for the web UI instead of CLI mode",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for the FastAPI server (default: 8000)",
    )

    args = parser.parse_args()

    if args.api:
        # Start FastAPI server
        try:
            import uvicorn
            from src.api import app

            print(f"🛡️  CodeSentinel API starting on http://localhost:{args.port}")
            uvicorn.run(app, host="0.0.0.0", port=args.port)
        except ImportError:
            print("Error: FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn")
            sys.exit(1)
    else:
        # Resolve repo path (clone if URL provided)
        try:
            repo_path = resolve_repo_path(args.repo, args.url, args.branch)
            result = run_audit(repo_path)
        except (FileNotFoundError, ValueError) as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n🛑 Audit cancelled.")
            sys.exit(130)


if __name__ == "__main__":
    main()
