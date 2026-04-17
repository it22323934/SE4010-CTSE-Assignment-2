"""Tests for the repository cloner tool."""

import json
from pathlib import Path

import pytest


class TestRepoCloner:
    """Tests for clone_repository tool."""

    def test_sanitize_repo_name_https(self):
        """Should extract owner__repo from HTTPS URLs."""
        from src.tools.repo_cloner import _sanitize_repo_name

        assert _sanitize_repo_name("https://github.com/pallets/flask") == "pallets__flask"
        assert _sanitize_repo_name("https://github.com/pallets/flask.git") == "pallets__flask"
        assert _sanitize_repo_name("https://gitlab.com/org/project/") == "org__project"

    def test_sanitize_repo_name_ssh(self):
        """Should extract owner__repo from SSH URLs."""
        from src.tools.repo_cloner import _sanitize_repo_name

        assert _sanitize_repo_name("git@github.com:owner/repo.git") == "owner__repo"
        assert _sanitize_repo_name("git@gitlab.com:my-org/my-project") == "my-org__my-project"

    def test_validate_git_url_valid(self):
        """Should accept valid Git URLs."""
        from src.tools.repo_cloner import _validate_git_url

        assert _validate_git_url("https://github.com/owner/repo") is True
        assert _validate_git_url("https://gitlab.com/owner/repo.git") is True
        assert _validate_git_url("git@github.com:owner/repo.git") is True

    def test_validate_git_url_invalid(self):
        """Should reject non-Git URLs."""
        from src.tools.repo_cloner import _validate_git_url

        assert _validate_git_url("/some/local/path") is False
        assert _validate_git_url("not a url") is False
        assert _validate_git_url("ftp://example.com/repo") is False

    def test_clone_invalid_url(self):
        """Should return error for invalid Git URL."""
        from src.tools.repo_cloner import clone_repository

        result = json.loads(clone_repository.invoke({
            "repo_url": "not-a-valid-url",
        }))

        assert result["status"] == "error"
        assert "Invalid Git URL" in result["error"]

    def test_clone_existing_local_repo(self, sample_repo: Path):
        """Should handle pull on already-cloned repo."""
        import shutil
        from src.config import CLONED_REPOS_DIR

        # Simulate an already-cloned repo by copying sample_repo
        fake_clone_dir = CLONED_REPOS_DIR / "test__existing"
        if fake_clone_dir.exists():
            shutil.rmtree(fake_clone_dir)
        shutil.copytree(sample_repo, fake_clone_dir)

        from src.tools.repo_cloner import clone_repository

        # This URL maps to test__existing via _sanitize_repo_name
        # We test that it detects the existing clone and tries to pull
        result = json.loads(clone_repository.invoke({
            "repo_url": "https://github.com/test/existing",
        }))

        # It should detect the existing clone (pull may fail on local-only repo, but action = updated)
        assert result["status"] == "success"
        assert result["action"] == "updated"
        assert "test__existing" in result["local_path"]

        # Cleanup
        shutil.rmtree(fake_clone_dir, ignore_errors=True)
