"""Git repository analysis tool for CodeSentinel.

Used by the Orchestrator (for planning) and Security Agent (for history scanning).
Provides repo metadata, recent changes, secret history scanning, and blame info.
"""

import json
import re
import subprocess
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field


class GitAnalyzerInput(BaseModel):
    """Input schema for the Git analyzer tool."""

    repo_path: str = Field(
        ...,
        description="Absolute path to the Git repository to analyze.",
    )
    operation: str = Field(
        ...,
        description=(
            "Operation to perform: 'repo_info' | 'recent_changes' | "
            "'search_history' | 'file_blame' | 'file_diff'"
        ),
    )
    params: dict | None = Field(
        default=None,
        description="Additional parameters for the operation (e.g., file_path, pattern, limit).",
    )


def _run_git(repo_path: str, args: list[str]) -> tuple[bool, str]:
    """Run a git command and return (success, output).

    Args:
        repo_path: Path to the git repository.
        args: Git command arguments (e.g., ['log', '--oneline']).

    Returns:
        Tuple of (success_bool, stdout_or_stderr).
    """
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "Git command timed out after 30 seconds"
    except FileNotFoundError:
        return False, "Git is not installed or not in PATH"


def _get_repo_info(repo_path: str) -> dict:
    """Get repository metadata: files, languages, last commit.

    Args:
        repo_path: Path to the git repository.

    Returns:
        Dict with repo metadata.
    """
    info: dict = {"repo_path": repo_path}

    # Get repo name
    info["repo_name"] = Path(repo_path).name

    # Get current branch
    ok, branch = _run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
    info["branch"] = branch if ok else "unknown"

    # Get current commit hash
    ok, commit = _run_git(repo_path, ["rev-parse", "HEAD"])
    info["commit_hash"] = commit[:12] if ok else "unknown"

    # Get file list
    ok, file_list = _run_git(repo_path, ["ls-files"])
    if ok:
        files = [f for f in file_list.split("\n") if f.strip()]
        info["total_files"] = len(files)

        # Detect languages by extension
        extensions: dict[str, int] = {}
        for f in files:
            ext = Path(f).suffix.lower()
            if ext:
                extensions[ext] = extensions.get(ext, 0) + 1

        info["file_extensions"] = extensions

        # Determine primary language
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "golang",
            ".rs": "rust",
            ".rb": "ruby",
            ".cpp": "c++",
            ".c": "c",
        }
        primary_ext = max(extensions, key=extensions.get) if extensions else ""
        info["language"] = lang_map.get(primary_ext, primary_ext.lstrip("."))

        # Detect framework (simple heuristics)
        info["framework"] = _detect_framework(repo_path, files, info["language"])

        # Source files only (exclude configs, tests, etc.)
        source_exts = {".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".cpp", ".c"}
        info["source_files"] = [f for f in files if Path(f).suffix.lower() in source_exts]
    else:
        info["total_files"] = 0
        info["source_files"] = []
        info["language"] = "unknown"
        info["framework"] = "unknown"

    # Get last commit info
    ok, log = _run_git(repo_path, ["log", "-1", "--format=%H|%an|%ae|%s|%ci"])
    if ok and "|" in log:
        parts = log.split("|", 4)
        info["last_commit"] = {
            "hash": parts[0][:12],
            "author": parts[1],
            "email": parts[2],
            "message": parts[3],
            "date": parts[4] if len(parts) > 4 else "",
        }

    return info


def _detect_framework(repo_path: str, files: list[str], language: str) -> str:
    """Detect the framework used in the project.

    Args:
        repo_path: Path to the repo.
        files: List of tracked files.
        language: Detected primary language.

    Returns:
        Framework name or 'unknown'.
    """
    file_set = set(files)

    if language == "python":
        # Check for common Python frameworks
        if "requirements.txt" in file_set:
            try:
                reqs = (Path(repo_path) / "requirements.txt").read_text(encoding="utf-8").lower()
                if "fastapi" in reqs:
                    return "fastapi"
                if "django" in reqs:
                    return "django"
                if "flask" in reqs:
                    return "flask"
            except OSError:
                pass
        if "pyproject.toml" in file_set:
            try:
                toml = (Path(repo_path) / "pyproject.toml").read_text(encoding="utf-8").lower()
                if "fastapi" in toml:
                    return "fastapi"
                if "django" in toml:
                    return "django"
                if "flask" in toml:
                    return "flask"
            except OSError:
                pass

    elif language == "javascript" or language == "typescript":
        if "package.json" in file_set:
            try:
                pkg = (Path(repo_path) / "package.json").read_text(encoding="utf-8").lower()
                if "react" in pkg:
                    return "react"
                if "express" in pkg:
                    return "express"
                if "next" in pkg:
                    return "nextjs"
            except OSError:
                pass

    return "unknown"


def _get_recent_changes(repo_path: str, limit: int = 10) -> list[dict]:
    """Get files changed in the last N commits, ranked by change frequency.

    Args:
        repo_path: Path to the git repository.
        limit: Number of recent commits to analyze.

    Returns:
        List of dicts with file_path and change_count, sorted by frequency.
    """
    ok, log = _run_git(repo_path, [
        "log", f"--max-count={limit}", "--name-only", "--format="
    ])
    if not ok:
        return []

    file_counts: dict[str, int] = {}
    for line in log.split("\n"):
        line = line.strip()
        if line:
            file_counts[line] = file_counts.get(line, 0) + 1

    # Sort by frequency descending
    sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"file_path": f, "change_count": c} for f, c in sorted_files]


def _search_git_history(repo_path: str, pattern: str) -> list[dict]:
    """Search all commits for a regex pattern (e.g., hardcoded secrets).

    Args:
        repo_path: Path to the git repository.
        pattern: Regex pattern to search for in diffs.

    Returns:
        List of dicts with commit, file, and matched content.
    """
    ok, output = _run_git(repo_path, [
        "log", "--all", "-p", f"--grep-reflog={pattern}",
        "--format=%H|%s|%ci", "-20"
    ])

    # Fallback: use git log -S for string search
    ok, output = _run_git(repo_path, [
        "log", "--all", f"-S{pattern}", "--format=%H|%s|%ci", "-20"
    ])

    if not ok or not output:
        return []

    results = []
    for line in output.split("\n"):
        if "|" in line:
            parts = line.split("|", 2)
            results.append({
                "commit": parts[0][:12],
                "message": parts[1] if len(parts) > 1 else "",
                "date": parts[2] if len(parts) > 2 else "",
            })

    return results


def _get_file_blame(repo_path: str, file_path: str) -> list[dict]:
    """Get blame information for a specific file.

    Args:
        repo_path: Path to the git repository.
        file_path: Relative path to the file within the repo.

    Returns:
        List of dicts with line, author, commit, date info.
    """
    ok, output = _run_git(repo_path, ["blame", "--line-porcelain", file_path])
    if not ok:
        return []

    blame_entries: list[dict] = []
    current: dict = {}

    for line in output.split("\n"):
        if line.startswith("author "):
            current["author"] = line[7:]
        elif line.startswith("author-time "):
            current["timestamp"] = line[12:]
        elif line.startswith("summary "):
            current["summary"] = line[8:]
        elif re.match(r"^[0-9a-f]{40}", line):
            parts = line.split()
            current = {"commit": parts[0][:12], "line": int(parts[2]) if len(parts) > 2 else 0}
        elif line.startswith("\t"):
            current["content"] = line[1:]
            blame_entries.append(current)
            current = {}

    return blame_entries[:100]  # Limit to 100 lines for sanity


@tool(args_schema=GitAnalyzerInput)
def git_analyzer(repo_path: str, operation: str, params: dict | None = None) -> str:
    """Analyze a Git repository's history, structure, and change patterns.

    Use this tool to understand a repository before auditing it. Operations:
    - 'repo_info': Get repo metadata (languages, file count, branches, framework)
    - 'recent_changes': Get files changed in last N commits (default: 10)
    - 'search_history': Search all commits for a regex pattern (e.g., secrets)
    - 'file_blame': Get blame info for a specific file
    - 'file_diff': Get diff for a specific file across last N commits

    Args:
        repo_path: Absolute path to the Git repository.
        operation: One of 'repo_info', 'recent_changes', 'search_history', 'file_blame'.
        params: Additional parameters depending on operation.

    Returns:
        JSON string with operation results.

    Raises:
        FileNotFoundError: If the repository path does not exist.
        ValueError: If an unknown operation is specified.
    """
    try:
        path = Path(repo_path)
        if not path.exists():
            return json.dumps({"status": "error", "error": f"Path not found: {repo_path}", "tool": "git_analyzer"})
        if not (path / ".git").exists():
            return json.dumps({"status": "error", "error": f"Not a Git repository: {repo_path}", "tool": "git_analyzer"})

        params = params or {}

        match operation:
            case "repo_info":
                data = _get_repo_info(repo_path)
            case "recent_changes":
                limit = params.get("limit", 10)
                data = _get_recent_changes(repo_path, limit)
            case "search_history":
                pattern = params.get("pattern", "")
                if not pattern:
                    return json.dumps({"status": "error", "error": "Pattern required for search_history", "tool": "git_analyzer"})
                data = _search_git_history(repo_path, pattern)
            case "file_blame":
                file_path = params.get("file_path", "")
                if not file_path:
                    return json.dumps({"status": "error", "error": "file_path required for file_blame", "tool": "git_analyzer"})
                data = _get_file_blame(repo_path, file_path)
            case _:
                return json.dumps({"status": "error", "error": f"Unknown operation: {operation}", "tool": "git_analyzer"})

        return json.dumps(
            {"status": "success", "data": data, "metadata": {"tool": "git_analyzer", "operation": operation}},
            indent=2,
            default=str,
        )

    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "git_analyzer"})
