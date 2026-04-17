"""Dependency vulnerability scanner for CodeSentinel.

Parses lock files (package-lock.json, requirements.txt, Pipfile.lock, etc.)
to extract dependency names + versions, then batch-queries the OSV.dev API
(https://api.osv.dev) for known vulnerabilities (CVEs, GHSAs).

No API key required — OSV.dev is a free, public vulnerability database
maintained by Google, covering npm, PyPI, Maven, Go, RubyGems, and more.

Used by the Security Agent to flag vulnerable dependencies (OWASP A06:2021).
"""

import json
import re
from pathlib import Path
from typing import Any

import urllib.request
import urllib.error

from langchain_core.tools import tool
from pydantic import BaseModel, Field

# --- OSV.dev API ---
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

# --- Ecosystem mapping ---
ECOSYSTEM_MAP: dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "go.sum": "Go",
    "Gemfile.lock": "RubyGems",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
}

# Files to search for in the repo
LOCK_FILE_NAMES = list(ECOSYSTEM_MAP.keys())

# Maximum packages to query in a single batch (OSV limit)
MAX_BATCH_SIZE = 1000


def _find_lock_files(repo_path: str) -> list[tuple[Path, str]]:
    """Find all dependency lock/manifest files in the repo.

    Args:
        repo_path: Absolute path to the repository root.

    Returns:
        List of (file_path, ecosystem) tuples.
    """
    root = Path(repo_path)
    found: list[tuple[Path, str]] = []

    for name, ecosystem in ECOSYSTEM_MAP.items():
        # Search root and one level of subdirectories
        for candidate in [root / name] + list(root.glob(f"*/{name}")):
            if candidate.is_file():
                found.append((candidate, ecosystem))

    return found


def _parse_package_lock(path: Path) -> list[dict[str, str]]:
    """Parse npm package-lock.json for dependency names and versions.

    Args:
        path: Path to package-lock.json.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    deps: list[dict[str, str]] = []

    # package-lock.json v2/v3 format (packages key)
    packages = data.get("packages", {})
    if packages:
        for pkg_path, info in packages.items():
            if not pkg_path:  # root package
                continue
            # Extract name from path: "node_modules/axios" -> "axios"
            name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
            version = info.get("version", "")
            if name and version:
                deps.append({"name": name, "version": version})
        return deps

    # package-lock.json v1 format (dependencies key)
    dependencies = data.get("dependencies", {})
    for name, info in dependencies.items():
        version = info.get("version", "")
        if version:
            deps.append({"name": name, "version": version})

    return deps


def _parse_requirements_txt(path: Path) -> list[dict[str, str]]:
    """Parse requirements.txt for package names and pinned versions.

    Args:
        path: Path to requirements.txt.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    deps: list[dict[str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Match: package==version or package>=version
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*[=~!><]=?\s*([0-9][A-Za-z0-9._-]*)", line)
        if match:
            deps.append({"name": match.group(1), "version": match.group(2)})

    return deps


def _parse_pipfile_lock(path: Path) -> list[dict[str, str]]:
    """Parse Pipfile.lock for package names and versions.

    Args:
        path: Path to Pipfile.lock.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    deps: list[dict[str, str]] = []
    for section in ("default", "develop"):
        packages = data.get(section, {})
        for name, info in packages.items():
            version = info.get("version", "").lstrip("=")
            if version:
                deps.append({"name": name, "version": version})

    return deps


def _parse_go_sum(path: Path) -> list[dict[str, str]]:
    """Parse go.sum for module names and versions.

    Args:
        path: Path to go.sum.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    deps: list[dict[str, str]] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2:
            name = parts[0]
            version = parts[1].split("/go.mod")[0].lstrip("v")
            key = f"{name}@{version}"
            if key not in seen:
                seen.add(key)
                deps.append({"name": name, "version": version})

    return deps


def _parse_yarn_lock(path: Path) -> list[dict[str, str]]:
    """Parse yarn.lock for package names and versions.

    Args:
        path: Path to yarn.lock.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    deps: list[dict[str, str]] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []

    # Match patterns like: "axios@^1.6.0": \n  version "1.7.2"
    current_name = None
    for line in content.splitlines():
        # Package declaration line
        name_match = re.match(r'^"?(@?[^@\s"]+)@', line)
        if name_match:
            current_name = name_match.group(1)
            continue

        # Version line
        if current_name:
            ver_match = re.match(r'^\s+version\s+"([^"]+)"', line)
            if ver_match:
                deps.append({"name": current_name, "version": ver_match.group(1)})
                current_name = None

    return deps


def _parse_cargo_lock(path: Path) -> list[dict[str, str]]:
    """Parse Cargo.lock for crate names and versions.

    Args:
        path: Path to Cargo.lock.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    deps: list[dict[str, str]] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []

    current_name = None
    for line in content.splitlines():
        line = line.strip()
        name_match = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if name_match:
            current_name = name_match.group(1)
            continue
        ver_match = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if ver_match and current_name:
            deps.append({"name": current_name, "version": ver_match.group(1)})
            current_name = None

    return deps


PARSERS = {
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "requirements.txt": _parse_requirements_txt,
    "Pipfile.lock": _parse_pipfile_lock,
    "go.sum": _parse_go_sum,
    "Cargo.lock": _parse_cargo_lock,
}


def _parse_lock_file(path: Path) -> list[dict[str, str]]:
    """Dispatch to the correct parser based on filename.

    Args:
        path: Path to the lock/manifest file.

    Returns:
        List of {"name": ..., "version": ...} dicts.
    """
    parser = PARSERS.get(path.name)
    if parser:
        return parser(path)

    # Fallback: try to read as requirements.txt format
    if path.name.endswith(".txt"):
        return _parse_requirements_txt(path)

    return []


def _query_osv_batch(
    packages: list[dict[str, str]], ecosystem: str
) -> list[dict[str, Any]]:
    """Batch-query OSV.dev API for known vulnerabilities.

    Args:
        packages: List of {"name": ..., "version": ...} dicts.
        ecosystem: The package ecosystem (e.g., "npm", "PyPI").

    Returns:
        List of result dicts from OSV, one per package query.
    """
    if not packages:
        return []

    # Build batch queries
    queries = []
    for pkg in packages[:MAX_BATCH_SIZE]:
        queries.append({
            "package": {
                "name": pkg["name"],
                "ecosystem": ecosystem,
            },
            "version": pkg["version"],
        })

    payload = json.dumps({"queries": queries}).encode("utf-8")

    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("results", [])
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return []


def _fetch_vuln_details(vuln_id: str) -> dict[str, Any] | None:
    """Fetch full vulnerability details from OSV.dev.

    Args:
        vuln_id: The vulnerability ID (e.g., "GHSA-xxx", "CVE-xxx").

    Returns:
        Full vulnerability record, or None on failure.
    """
    url = f"{OSV_VULN_URL}/{vuln_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def _extract_severity(vuln: dict) -> str:
    """Extract severity from an OSV vulnerability record.

    Args:
        vuln: OSV vulnerability record.

    Returns:
        Severity string: "critical", "high", "medium", or "low".
    """
    # Check database_specific severity
    for affected in vuln.get("affected", []):
        eco_sev = affected.get("ecosystem_specific", {}).get("severity", "")
        if eco_sev:
            return eco_sev.lower()

        db_sev = affected.get("database_specific", {}).get("severity", "")
        if db_sev:
            return db_sev.lower()

    # Check CVSS in severity array
    severities = vuln.get("severity", [])
    for sev in severities:
        score_str = sev.get("score", "")
        sev_type = sev.get("type", "")

        if sev_type == "CVSS_V3" and score_str:
            # Parse CVSS vector for severity
            if "AV:N" in score_str and "AC:L" in score_str:
                return "critical"
            return "high"

    # Check aliases for CVE pattern (generic fallback)
    return "medium"


def _extract_fix_version(vuln: dict, pkg_name: str) -> str | None:
    """Extract the fixed version from an OSV vulnerability record.

    Args:
        vuln: OSV vulnerability record.
        pkg_name: Name of the affected package.

    Returns:
        Fix version string, or None if not available.
    """
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == pkg_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


class DependencyScannerInput(BaseModel):
    """Input schema for the dependency scanner tool."""

    repo_path: str = Field(
        ...,
        description="Absolute path to the repository root to scan for dependency vulnerabilities.",
    )
    max_details: int = Field(
        default=20,
        description=(
            "Maximum number of vulnerabilities to fetch full details for. "
            "Higher values give more info but take longer (one HTTP call per vuln)."
        ),
    )


@tool(args_schema=DependencyScannerInput)
def dependency_scanner(repo_path: str, max_details: int = 20) -> str:
    """Scan project dependencies for known vulnerabilities using OSV.dev.

    Detects lock files (package-lock.json, requirements.txt, Pipfile.lock,
    yarn.lock, go.sum, Cargo.lock), extracts package names and versions,
    then batch-queries the OSV.dev public vulnerability database.

    Returns structured findings with CVE/GHSA IDs, severity, descriptions,
    and fix versions for each vulnerable dependency.

    This tool covers OWASP A06:2021 — Vulnerable and Outdated Components.

    Args:
        repo_path: Absolute path to the repository root.
        max_details: Max vulns to fetch full details for (default 20).

    Returns:
        JSON string with dependency vulnerability findings.

    Raises:
        FileNotFoundError: If repo_path does not exist.
    """
    try:
        root = Path(repo_path)
        if not root.exists():
            return json.dumps({
                "status": "error",
                "error": f"Repository path not found: {repo_path}",
                "tool": "dependency_scanner",
            })

        # Step 1: Find lock files
        lock_files = _find_lock_files(repo_path)
        if not lock_files:
            return json.dumps({
                "status": "success",
                "data": {
                    "lock_files_found": 0,
                    "total_dependencies": 0,
                    "vulnerable_count": 0,
                    "vulnerabilities": [],
                    "message": "No dependency lock files found in repository.",
                },
                "tool": "dependency_scanner",
            })

        all_vulns: list[dict] = []
        total_deps = 0
        scanned_files: list[dict] = []

        # Step 2: Parse each lock file and query OSV
        for lock_path, ecosystem in lock_files:
            rel_path = str(lock_path.relative_to(root))
            packages = _parse_lock_file(lock_path)
            total_deps += len(packages)

            scanned_files.append({
                "file": rel_path,
                "ecosystem": ecosystem,
                "dependency_count": len(packages),
            })

            if not packages:
                continue

            # Step 3: Batch query OSV.dev
            results = _query_osv_batch(packages, ecosystem)

            # Step 4: Match results to packages
            for i, result in enumerate(results):
                if i >= len(packages):
                    break

                vulns_list = result.get("vulns", [])
                if not vulns_list:
                    continue

                pkg = packages[i]

                for vuln_ref in vulns_list:
                    vuln_id = vuln_ref.get("id", "unknown")

                    all_vulns.append({
                        "vuln_id": vuln_id,
                        "package": pkg["name"],
                        "installed_version": pkg["version"],
                        "ecosystem": ecosystem,
                        "lock_file": rel_path,
                        "modified": vuln_ref.get("modified"),
                    })

        # Step 5: Fetch full details for top vulnerabilities (deduplicated)
        seen_vuln_ids: set[str] = set()
        unique_vulns: list[dict] = []
        for v in all_vulns:
            if v["vuln_id"] not in seen_vuln_ids:
                seen_vuln_ids.add(v["vuln_id"])
                unique_vulns.append(v)

        enriched: list[dict] = []
        detail_count = 0

        for vuln in unique_vulns:
            vuln_entry: dict[str, Any] = {
                "vuln_id": vuln["vuln_id"],
                "package": vuln["package"],
                "installed_version": vuln["installed_version"],
                "ecosystem": vuln["ecosystem"],
                "lock_file": vuln["lock_file"],
            }

            # Fetch full details for up to max_details vulns
            if detail_count < max_details:
                details = _fetch_vuln_details(vuln["vuln_id"])
                if details:
                    detail_count += 1
                    vuln_entry["summary"] = details.get("summary", "")
                    vuln_entry["details"] = (details.get("details", "") or "")[:500]
                    vuln_entry["severity"] = _extract_severity(details)
                    vuln_entry["fix_version"] = _extract_fix_version(
                        details, vuln["package"]
                    )
                    vuln_entry["aliases"] = details.get("aliases", [])
                    vuln_entry["references"] = [
                        ref.get("url", "")
                        for ref in (details.get("references", []) or [])[:3]
                    ]
                else:
                    vuln_entry["severity"] = "medium"
                    vuln_entry["summary"] = f"Known vulnerability {vuln['vuln_id']}"
            else:
                vuln_entry["severity"] = "medium"
                vuln_entry["summary"] = f"Known vulnerability {vuln['vuln_id']} (details not fetched)"

            enriched.append(vuln_entry)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        enriched.sort(key=lambda v: severity_order.get(v.get("severity", "medium"), 2))

        # Build severity summary
        severity_counts: dict[str, int] = {}
        for v in enriched:
            sev = v.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return json.dumps({
            "status": "success",
            "data": {
                "lock_files_found": len(scanned_files),
                "scanned_files": scanned_files,
                "total_dependencies": total_deps,
                "vulnerable_count": len(enriched),
                "severity_summary": severity_counts,
                "vulnerabilities": enriched,
            },
            "tool": "dependency_scanner",
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "tool": "dependency_scanner",
        })
