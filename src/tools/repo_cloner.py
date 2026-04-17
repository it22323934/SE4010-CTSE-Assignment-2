"""Repository cloning tool for CodeSentinel.

Clones remote Git repositories into a dedicated local folder
for analysis. Supports GitHub, GitLab, Bitbucket, and any
public Git URL. Reuses existing clones to avoid redundant downloads.
"""

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from src.config import CLONED_REPOS_DIR


def _sanitize_repo_name(url: str) -> str:
    """Extract a safe directory name from a Git URL.

    Args:
        url: The Git repository URL.

    Returns:
        A sanitized directory name derived from the URL.
    """
    # Strip .git suffix and trailing slashes
    cleaned = url.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    # Extract owner/repo from common URL patterns
    # Handles: https://github.com/owner/repo, git@github.com:owner/repo
    match = re.search(r"[/:]([^/:]+)/([^/:]+)$", cleaned)
    if match:
        owner, repo = match.group(1), match.group(2)
        # Sanitize: only allow alphanumeric, hyphens, underscores, dots
        owner = re.sub(r"[^\w\-.]", "_", owner)
        repo = re.sub(r"[^\w\-.]", "_", repo)
        return f"{owner}__{repo}"

    # Fallback: use last path segment
    name = cleaned.split("/")[-1].split(":")[-1]
    return re.sub(r"[^\w\-.]", "_", name) or "unknown_repo"


def _validate_git_url(url: str) -> bool:
    """Validate that a string looks like a Git URL.

    Args:
        url: The URL to validate.

    Returns:
        True if it matches known Git URL patterns.
    """
    patterns = [
        r"^https?://[\w.\-]+/[\w.\-]+/[\w.\-]+",       # HTTPS
        r"^git@[\w.\-]+:[\w.\-]+/[\w.\-]+",             # SSH
        r"^ssh://[\w.\-]+@[\w.\-]+/[\w.\-]+/[\w.\-]+",  # SSH explicit
    ]
    return any(re.match(p, url) for p in patterns)


class RepoCloneInput(BaseModel):
    """Input schema for the repository cloner tool."""

    repo_url: str = Field(
        ...,
        description="Git repository URL (HTTPS or SSH) to clone.",
    )
    branch: str | None = Field(
        default=None,
        description="Optional branch name to checkout after cloning. Defaults to the repo's default branch.",
    )
    force_reclone: bool = Field(
        default=False,
        description="If True, delete the existing clone and re-clone from scratch.",
    )


@tool(args_schema=RepoCloneInput)
def clone_repository(repo_url: str, branch: str | None = None, force_reclone: bool = False) -> str:
    """Clone a remote Git repository into the local cloned_repos directory.

    Use this tool to fetch a remote repository for analysis. The repo is cloned
    into data/cloned_repos/<owner>__<repo>/. If it already exists, it pulls
    the latest changes instead of re-cloning (unless force_reclone is True).

    Args:
        repo_url: HTTPS or SSH URL of the Git repository.
        branch: Optional branch to checkout. Defaults to the repo's default branch.
        force_reclone: Delete existing clone and start fresh.

    Returns:
        JSON with the local path to the cloned repository.

    Raises:
        ValueError: If the URL is not a valid Git URL.
        subprocess.CalledProcessError: If the git command fails.
    """
    try:
        # Validate URL
        if not _validate_git_url(repo_url):
            return json.dumps({
                "status": "error",
                "error": f"Invalid Git URL: {repo_url}. Use HTTPS (https://github.com/owner/repo) or SSH (git@github.com:owner/repo).",
                "tool": "clone_repository",
            })

        repo_name = _sanitize_repo_name(repo_url)
        clone_path = CLONED_REPOS_DIR / repo_name

        # Force reclone: remove existing directory
        if force_reclone and clone_path.exists():
            def _on_rm_error(_func: object, path: str, _exc: object) -> None:
                """Handle read-only files (e.g. .git/objects/pack on Windows)."""
                os.chmod(path, stat.S_IWRITE)
                os.unlink(path)
            shutil.rmtree(clone_path, onexc=_on_rm_error)

        if clone_path.exists() and (clone_path / ".git").exists():
            # Repository already cloned — pull latest changes
            pull_cmd = ["git", "-C", str(clone_path), "pull", "--ff-only"]
            result = subprocess.run(
                pull_cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if branch:
                subprocess.run(
                    ["git", "-C", str(clone_path), "checkout", branch],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

            return json.dumps({
                "status": "success",
                "action": "updated",
                "local_path": str(clone_path),
                "repo_url": repo_url,
                "branch": branch or "default",
                "message": f"Pulled latest changes into existing clone at {clone_path}",
                "tool": "clone_repository",
            })
        else:
            # Fresh clone
            clone_cmd = ["git", "clone", "--depth", "50"]
            if branch:
                clone_cmd.extend(["--branch", branch])
            clone_cmd.extend([repo_url, str(clone_path)])

            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                return json.dumps({
                    "status": "error",
                    "error": f"git clone failed: {result.stderr.strip()}",
                    "tool": "clone_repository",
                })

            return json.dumps({
                "status": "success",
                "action": "cloned",
                "local_path": str(clone_path),
                "repo_url": repo_url,
                "branch": branch or "default",
                "message": f"Cloned {repo_url} to {clone_path}",
                "tool": "clone_repository",
            })

    except subprocess.TimeoutExpired:
        return json.dumps({
            "status": "error",
            "error": "Git operation timed out. Check your network connection.",
            "tool": "clone_repository",
        })
    except OSError as e:
        return json.dumps({
            "status": "error",
            "error": f"File system error: {e}",
            "tool": "clone_repository",
        })
