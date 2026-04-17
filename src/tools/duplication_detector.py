"""Code duplication detection tool for CodeSentinel.

Detects duplicated code blocks across files in a repository using
normalized line hashing. Identifies copy-paste patterns, repeated logic,
and opportunities for shared utility extraction.

Used by the Code Quality Agent to flag DRY violations.
"""

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

# Minimum consecutive matching lines to flag as a duplicate
MIN_DUPLICATE_LINES = 6
# Extensions to scan
SCANNABLE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb"}


def _normalize_line(line: str) -> str:
    """Normalize a line for comparison.

    Strips whitespace, comments, and normalizes variable names to reduce
    false negatives from cosmetic differences.

    Args:
        line: Raw source line.

    Returns:
        Normalized line string, or empty string for non-code lines.
    """
    stripped = line.strip()

    # Skip empty lines, comments, imports
    if not stripped:
        return ""
    if stripped.startswith(("#", "//", "/*", "*", "import ", "from ", "require(")):
        return ""
    if stripped in ("{", "}", "};", ");", "],", "],"):
        return ""

    # Remove inline comments
    stripped = re.sub(r"\s*//.*$", "", stripped)
    stripped = re.sub(r"\s*#.*$", "", stripped)

    # Collapse whitespace
    stripped = re.sub(r"\s+", " ", stripped)

    return stripped


def _hash_line(line: str) -> str | None:
    """Hash a normalized line. Returns None for empty/skip lines."""
    normalized = _normalize_line(line)
    if not normalized:
        return None
    return hashlib.md5(normalized.encode("utf-8")).hexdigest()


def _find_duplicates_in_files(
    file_contents: dict[str, list[str]],
    min_lines: int = MIN_DUPLICATE_LINES,
) -> list[dict]:
    """Find duplicate code blocks across multiple files.

    Uses a sliding-window hash approach: hash sequences of `min_lines`
    consecutive non-empty lines, then group matching sequences.

    Args:
        file_contents: Dict mapping relative file paths to their lines.
        min_lines: Minimum consecutive lines to consider a duplicate.

    Returns:
        List of duplicate group dicts with file locations.
    """
    # Build hash sequences: for each file, create rolling hashes of min_lines blocks
    block_index: dict[str, list[dict]] = defaultdict(list)

    for file_path, lines in file_contents.items():
        # Build list of (original_line_num, hash) for non-empty lines
        hashed_lines: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            h = _hash_line(line)
            if h is not None:
                hashed_lines.append((i + 1, h))  # 1-indexed line number

        if len(hashed_lines) < min_lines:
            continue

        # Create block hashes from consecutive lines
        for start_idx in range(len(hashed_lines) - min_lines + 1):
            block = hashed_lines[start_idx:start_idx + min_lines]
            block_hash = hashlib.md5(
                "".join(h for _, h in block).encode()
            ).hexdigest()

            block_index[block_hash].append({
                "file": file_path,
                "line_start": block[0][0],
                "line_end": block[-1][0],
            })

    # Filter to only blocks that appear in 2+ locations
    duplicates: list[dict] = []
    seen_pairs: set[str] = set()

    for block_hash, locations in block_index.items():
        if len(locations) < 2:
            continue

        # Deduplicate overlapping ranges in the same file
        unique_locations: list[dict] = []
        for loc in locations:
            key = f"{loc['file']}:{loc['line_start']}"
            if key not in seen_pairs:
                unique_locations.append(loc)

        if len(unique_locations) < 2:
            continue

        # Mark these as seen
        for loc in unique_locations:
            seen_pairs.add(f"{loc['file']}:{loc['line_start']}")

        # Get a code snippet from the first location for context
        first = unique_locations[0]
        first_lines = file_contents.get(first["file"], [])
        snippet_start = first["line_start"] - 1
        snippet_end = min(first["line_end"], len(first_lines))
        snippet = "\n".join(first_lines[snippet_start:snippet_end])

        duplicates.append({
            "block_hash": block_hash[:12],
            "line_count": unique_locations[0]["line_end"] - unique_locations[0]["line_start"] + 1,
            "locations": unique_locations,
            "snippet_preview": snippet[:200],
        })

    # Sort by line count descending (largest duplicates first) and limit
    duplicates.sort(key=lambda d: d["line_count"], reverse=True)
    return duplicates[:30]  # Cap at 30 to avoid overwhelming output


class DuplicationDetectorInput(BaseModel):
    """Input schema for the duplication detector tool."""

    repo_path: str = Field(
        ...,
        description="Absolute path to the repository root to scan.",
    )
    target_files: list[str] = Field(
        default=[],
        description="Optional list of relative file paths to scan. If empty, scans all supported files.",
    )
    min_lines: int = Field(
        default=MIN_DUPLICATE_LINES,
        description="Minimum number of consecutive matching lines to flag as a duplicate.",
    )


@tool(args_schema=DuplicationDetectorInput)
def detect_code_duplication(repo_path: str, target_files: list[str] | None = None, min_lines: int = MIN_DUPLICATE_LINES) -> str:
    """Detect duplicated code blocks across files in a repository.

    Scans source files, normalizes lines (stripping comments, whitespace),
    and uses rolling hash comparison to find copy-paste code that should
    be extracted into shared utilities or common modules.

    Args:
        repo_path: Absolute path to the repository root.
        target_files: Optional list of specific files to scan (relative paths).
        min_lines: Minimum consecutive matching lines to flag.

    Returns:
        JSON string with duplicate groups, each containing file locations
        and a code snippet preview.

    Raises:
        FileNotFoundError: If the repository path does not exist.
    """
    root = Path(repo_path)
    if not root.exists():
        return json.dumps({"error": f"Repo path not found: {repo_path}", "duplicates": []})

    file_contents: dict[str, list[str]] = {}

    if target_files:
        files_to_scan = [root / f for f in target_files]
    else:
        files_to_scan = []
        for ext in SCANNABLE_EXTENSIONS:
            files_to_scan.extend(root.rglob(f"*{ext}"))

    for file_path in files_to_scan:
        if not file_path.is_file():
            continue

        # Skip common non-source directories
        rel = str(file_path.relative_to(root))
        skip_dirs = ("node_modules", ".git", "__pycache__", "dist", "build", ".venv", "venv", ".next")
        if any(part in rel.split("/") or part in rel.split("\\") for part in skip_dirs):
            continue

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").split("\n")
            file_contents[rel.replace("\\", "/")] = lines
        except OSError:
            continue

    if not file_contents:
        return json.dumps({"status": "success", "files_scanned": 0, "duplicates": []})

    duplicates = _find_duplicates_in_files(file_contents, min_lines=min_lines)

    # Build findings from duplicates
    findings: list[dict] = []
    for dup in duplicates:
        locs = dup["locations"]
        loc_strs = [f"`{loc['file']}` (L{loc['line_start']}-{loc['line_end']})" for loc in locs]

        findings.append({
            "category": "code_duplication",
            "severity": "medium" if dup["line_count"] < 15 else "high",
            "locations": locs,
            "line_count": dup["line_count"],
            "description": f"Duplicated code block ({dup['line_count']} lines) found in: {', '.join(loc_strs)}.",
            "suggestion": "Extract this repeated logic into a shared utility function or common module to follow DRY principle.",
            "snippet_preview": dup["snippet_preview"],
        })

    return json.dumps({
        "status": "success",
        "files_scanned": len(file_contents),
        "duplicate_groups": len(findings),
        "findings": findings,
    }, indent=2)
