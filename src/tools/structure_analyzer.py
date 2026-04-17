"""Project structure and design pattern analyzer for CodeSentinel.

Analyzes repository folder layout, detects framework conventions,
suggests design patterns to reduce complexity, and identifies
opportunities for shared utility extraction.

Used by the Code Quality Agent to provide architecture-level insights.
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Framework detection heuristics
# ---------------------------------------------------------------------------

FRAMEWORK_SIGNATURES: dict[str, dict] = {
    "react": {
        "files": ["package.json"],
        "content_patterns": {"package.json": [r'"react"', r'"react-dom"']},
        "recommended_structure": {
            "src/components/": "Reusable UI components (one folder per component with index + styles + test)",
            "src/hooks/": "Custom React hooks (useAuth, useFetch, etc.)",
            "src/pages/": "Page-level components (one per route)",
            "src/utils/": "Pure utility functions (formatters, validators, helpers)",
            "src/services/": "API calls and external service wrappers",
            "src/context/": "React Context providers and consumers",
            "src/constants/": "App-wide constants and enums",
            "src/types/": "TypeScript type definitions and interfaces",
            "src/assets/": "Static assets (images, fonts, icons)",
        },
    },
    "next.js": {
        "files": ["next.config.js", "next.config.mjs", "next.config.ts"],
        "content_patterns": {"package.json": [r'"next"']},
        "recommended_structure": {
            "app/": "App Router pages and layouts (Next.js 13+)",
            "components/": "Shared UI components",
            "lib/": "Utility functions, database clients, shared logic",
            "hooks/": "Custom React hooks",
            "services/": "API service layers",
            "types/": "TypeScript types",
            "public/": "Static assets served at root",
        },
    },
    "express": {
        "files": [],
        "content_patterns": {"package.json": [r'"express"']},
        "recommended_structure": {
            "src/routes/": "Route definitions grouped by resource",
            "src/controllers/": "Request handler logic (thin controllers)",
            "src/services/": "Business logic layer",
            "src/models/": "Database models / schemas",
            "src/middleware/": "Express middleware (auth, logging, validation)",
            "src/utils/": "Shared utility functions",
            "src/config/": "Environment and app configuration",
            "src/validators/": "Input validation schemas (Joi, Zod)",
        },
    },
    "django": {
        "files": ["manage.py"],
        "content_patterns": {"manage.py": [r"django"]},
        "recommended_structure": {
            "<app>/models.py": "Database models",
            "<app>/views.py": "View logic (keep thin — delegate to services)",
            "<app>/services.py": "Business logic layer (not default — add manually)",
            "<app>/serializers.py": "DRF serializers for API responses",
            "<app>/urls.py": "URL routing per app",
            "<app>/tests/": "Tests organized per module",
            "utils/": "Cross-app utility functions",
        },
    },
    "flask": {
        "files": [],
        "content_patterns": {"*.py": [r"from flask import|import flask"]},
        "recommended_structure": {
            "app/": "Application package with __init__.py factory",
            "app/routes/": "Blueprint route definitions",
            "app/models/": "Database models",
            "app/services/": "Business logic",
            "app/utils/": "Shared utilities",
            "app/templates/": "Jinja2 templates",
            "config.py": "App configuration",
        },
    },
    "spring": {
        "files": ["pom.xml", "build.gradle"],
        "content_patterns": {"pom.xml": [r"spring-boot"], "build.gradle": [r"spring-boot"]},
        "recommended_structure": {
            "src/main/java/<pkg>/controller/": "REST controllers",
            "src/main/java/<pkg>/service/": "Business logic services",
            "src/main/java/<pkg>/repository/": "Data access layer",
            "src/main/java/<pkg>/model/": "Domain entities",
            "src/main/java/<pkg>/dto/": "Data transfer objects",
            "src/main/java/<pkg>/config/": "Spring configuration classes",
            "src/main/java/<pkg>/exception/": "Custom exception classes",
        },
    },
    "python_generic": {
        "files": ["setup.py", "pyproject.toml"],
        "content_patterns": {},
        "recommended_structure": {
            "src/<pkg>/": "Main source package",
            "src/<pkg>/utils/": "Shared utility functions",
            "src/<pkg>/models/": "Data models (Pydantic, dataclasses)",
            "src/<pkg>/services/": "Business logic layer",
            "tests/": "Test files mirroring source structure",
            "config/": "Configuration files",
        },
    },
}

# Design pattern suggestions based on code patterns
DESIGN_PATTERN_SUGGESTIONS: list[dict] = [
    {
        "pattern_name": "Utility Module / Helper Extraction",
        "trigger": "repeated_functions",
        "description": "Multiple files contain similar helper functions (formatters, validators, parsers).",
        "suggestion": "Create a `utils/` or `helpers/` module and centralize these functions. Group by domain: `utils/formatters.py`, `utils/validators.py`, etc.",
        "complexity_reduction": "high",
    },
    {
        "pattern_name": "Service Layer Pattern",
        "trigger": "fat_controllers",
        "description": "Route handlers / controllers contain business logic mixed with HTTP concerns.",
        "suggestion": "Extract business logic into a `services/` layer. Controllers should only handle request parsing, call services, and format responses.",
        "complexity_reduction": "high",
    },
    {
        "pattern_name": "Repository Pattern",
        "trigger": "scattered_db_queries",
        "description": "Database queries are scattered across multiple files instead of being centralized.",
        "suggestion": "Create a `repositories/` or `data/` layer that encapsulates all database operations. Use a consistent interface (e.g., `find_by_id`, `create`, `update`).",
        "complexity_reduction": "medium",
    },
    {
        "pattern_name": "Factory Pattern",
        "trigger": "complex_initialization",
        "description": "Complex object creation logic is repeated or scattered.",
        "suggestion": "Use a Factory function/class to encapsulate object creation. This centralizes initialization and makes testing easier.",
        "complexity_reduction": "medium",
    },
    {
        "pattern_name": "Strategy Pattern",
        "trigger": "large_switch_if",
        "description": "Large switch/case or if-elif chains that select behavior based on a type/mode.",
        "suggestion": "Replace with Strategy pattern: define a common interface and implement each case as a separate class/function. Use a dict mapping to select the right strategy.",
        "complexity_reduction": "high",
    },
    {
        "pattern_name": "Custom Hook Extraction (React)",
        "trigger": "duplicated_react_logic",
        "description": "Multiple React components share the same stateful logic (useState + useEffect patterns).",
        "suggestion": "Extract shared logic into a custom hook (`useXxx`). This follows React's composition model and the DRY principle.",
        "complexity_reduction": "medium",
    },
    {
        "pattern_name": "Configuration Object Pattern",
        "trigger": "many_parameters",
        "description": "Functions accept many parameters (>5), making calls verbose and error-prone.",
        "suggestion": "Group related parameters into a configuration object or use the Builder pattern. In Python, use a Pydantic model or dataclass.",
        "complexity_reduction": "medium",
    },
    {
        "pattern_name": "Middleware / Decorator Pattern",
        "trigger": "cross_cutting_concerns",
        "description": "Cross-cutting concerns (logging, auth, validation) are repeated in multiple handlers.",
        "suggestion": "Extract into middleware (Express/Django) or decorators (Python). Apply once instead of repeating in every handler.",
        "complexity_reduction": "high",
    },
]


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def _detect_framework(repo_path: Path) -> list[str]:
    """Detect which frameworks a repository uses.

    Args:
        repo_path: Path to the repository root.

    Returns:
        List of detected framework names.
    """
    detected: list[str] = []

    for fw_name, fw_config in FRAMEWORK_SIGNATURES.items():
        # Check for marker files
        for marker_file in fw_config["files"]:
            if (repo_path / marker_file).exists():
                # If there are content patterns to verify, check them
                patterns = fw_config["content_patterns"].get(marker_file, [])
                if patterns:
                    try:
                        content = (repo_path / marker_file).read_text(encoding="utf-8", errors="replace")
                        if all(re.search(p, content) for p in patterns):
                            detected.append(fw_name)
                            break
                    except OSError:
                        continue
                else:
                    detected.append(fw_name)
                    break

        # Check content patterns for files that don't have specific marker files
        if fw_name not in detected:
            for file_glob, patterns in fw_config["content_patterns"].items():
                if file_glob.startswith("*"):
                    # Glob search
                    for f in repo_path.glob(file_glob):
                        try:
                            content = f.read_text(encoding="utf-8", errors="replace")
                            if all(re.search(p, content) for p in patterns):
                                detected.append(fw_name)
                                break
                        except OSError:
                            continue
                else:
                    target = repo_path / file_glob
                    if target.exists():
                        try:
                            content = target.read_text(encoding="utf-8", errors="replace")
                            if all(re.search(p, content) for p in patterns):
                                detected.append(fw_name)
                        except OSError:
                            continue

    return list(set(detected))


def _analyze_folder_structure(
    repo_path: Path,
    frameworks: list[str],
) -> dict:
    """Analyze the repository's folder structure against best practices.

    Args:
        repo_path: Path to the repository root.
        frameworks: Detected frameworks.

    Returns:
        Dict with current structure, recommendations, and missing folders.
    """
    skip_dirs = {"node_modules", ".git", "__pycache__", "dist", "build", ".venv",
                 "venv", ".next", ".cache", "coverage", ".mypy_cache", ".pytest_cache"}

    # Collect current folder structure
    current_dirs: set[str] = set()
    file_extensions: Counter = Counter()
    files_per_dir: dict[str, int] = defaultdict(int)

    for item in repo_path.rglob("*"):
        rel = item.relative_to(repo_path)
        parts = rel.parts
        if any(p in skip_dirs for p in parts):
            continue
        if item.is_dir():
            current_dirs.add(str(rel).replace("\\", "/") + "/")
        elif item.is_file():
            file_extensions[item.suffix.lower()] += 1
            parent_dir = str(rel.parent).replace("\\", "/")
            files_per_dir[parent_dir] += 1

    # Gather recommendations from detected frameworks
    recommendations: list[dict] = []
    missing_dirs: list[str] = []

    for fw in frameworks:
        fw_config = FRAMEWORK_SIGNATURES.get(fw, {})
        recommended = fw_config.get("recommended_structure", {})

        for folder, purpose in recommended.items():
            if "<" in folder:
                continue  # Skip template patterns

            # Check if this folder (or similar) exists
            folder_norm = folder.rstrip("/")
            exists = any(
                d.rstrip("/") == folder_norm or d.startswith(folder_norm + "/")
                for d in current_dirs
            )

            if not exists:
                missing_dirs.append(folder)
                recommendations.append({
                    "folder": folder,
                    "purpose": purpose,
                    "framework": fw,
                    "severity": "medium",
                    "type": "missing_folder",
                })

    # Check for files in root that should be in subdirectories
    root_files = files_per_dir.get(".", 0)
    if root_files > 10:
        recommendations.append({
            "folder": "src/",
            "purpose": f"Root directory has {root_files} files. Organize source code into a `src/` directory.",
            "framework": "general",
            "severity": "medium",
            "type": "cluttered_root",
        })

    # Check for oversized directories
    for dir_path, count in files_per_dir.items():
        if count > 20 and dir_path != ".":
            recommendations.append({
                "folder": dir_path,
                "purpose": f"Directory has {count} files — consider splitting into subdirectories by feature or responsibility.",
                "framework": "general",
                "severity": "low",
                "type": "large_directory",
            })

    return {
        "total_directories": len(current_dirs),
        "file_extensions": dict(file_extensions.most_common(15)),
        "files_per_dir_top": dict(
            sorted(files_per_dir.items(), key=lambda x: x[1], reverse=True)[:10]
        ),
        "missing_recommended_dirs": missing_dirs,
        "recommendations": recommendations,
    }


def _detect_pattern_opportunities(
    repo_path: Path,
    priority_files: list[str],
) -> list[dict]:
    """Detect opportunities for design pattern application.

    Scans priority files for code patterns that suggest a design pattern
    would reduce complexity.

    Args:
        repo_path: Path to the repository root.
        priority_files: List of relative file paths to analyze.

    Returns:
        List of pattern suggestion dicts.
    """
    suggestions: list[dict] = []

    # Counters for cross-file patterns
    function_names: dict[str, list[str]] = defaultdict(list)  # name -> [file1, file2]
    has_large_switch = False
    has_fat_controller = False
    has_scattered_queries = False
    has_many_params = False
    react_hook_patterns: dict[str, list[str]] = defaultdict(list)

    for file_rel in priority_files:
        abs_path = repo_path / file_rel
        if not abs_path.is_file():
            continue

        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        ext = abs_path.suffix.lower()

        # Track function names across files (for duplication/utility extraction)
        if ext == ".py":
            for m in re.finditer(r"def\s+(\w+)\s*\(", source):
                function_names[m.group(1)].append(file_rel)
        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            for m in re.finditer(r"(?:function|const|let)\s+(\w+)\s*(?:=\s*(?:async\s*)?\()?\s*\(", source):
                function_names[m.group(1)].append(file_rel)

        # Detect large switch/if-elif chains (Strategy pattern opportunity)
        switch_count = len(re.findall(r"\bcase\s+", source))
        elif_count = len(re.findall(r"\belif\s+|\belse\s+if\s+", source))
        if switch_count > 8 or elif_count > 5:
            has_large_switch = True
            suggestions.append({
                "file": file_rel,
                "pattern_name": "Strategy Pattern",
                "description": f"Large conditional chain ({switch_count} cases / {elif_count} elif branches) in `{file_rel}`.",
                "suggestion": "Replace with Strategy pattern: use a dict mapping or polymorphism to dispatch behavior.",
                "severity": "medium",
            })

        # Detect fat controllers (business logic in route handlers)
        is_route_file = any(kw in file_rel.lower() for kw in ("route", "controller", "view", "handler", "endpoint"))
        if is_route_file and len(source.split("\n")) > 200:
            has_fat_controller = True

        # Detect scattered DB queries
        db_patterns = len(re.findall(
            r"\.find\(|\.findOne\(|\.aggregate\(|\.query\(|\.execute\(|\.select\(|\.insert\(|\.update\(|\.delete\(",
            source
        ))
        if db_patterns > 3 and not any(kw in file_rel.lower() for kw in ("model", "repo", "database", "db", "query")):
            has_scattered_queries = True

        # Detect functions with many parameters
        many_params = re.findall(r"(?:def|function)\s+\w+\s*\(([^)]{100,})\)", source)
        for params_str in many_params:
            param_count = len([p for p in params_str.split(",") if p.strip()])
            if param_count > 5:
                has_many_params = True

        # Detect duplicated React hook patterns
        if ext in {".jsx", ".tsx"}:
            hook_blocks = re.findall(
                r"(const\s+\[.*?\]\s*=\s*useState.*?(?:\n.*?useEffect.*?\n.*?){0,5})",
                source, re.DOTALL,
            )
            for block in hook_blocks:
                block_key = re.sub(r"\w+", "X", block)[:100]  # Normalize
                react_hook_patterns[block_key].append(file_rel)

    # Cross-file analysis: functions with same name in multiple files
    shared_functions = {
        name: files for name, files in function_names.items()
        if len(set(files)) > 1 and name not in (
            "__init__", "main", "setup", "teardown", "test", "render",
            "get", "post", "put", "delete", "index", "create", "update",
        )
    }

    if shared_functions:
        top_shared = sorted(shared_functions.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        for name, files in top_shared:
            unique_files = list(set(files))
            suggestions.append({
                "file": unique_files[0],
                "pattern_name": "Utility Module / Helper Extraction",
                "description": f"Function `{name}` appears in {len(unique_files)} files: {', '.join(unique_files[:3])}.",
                "suggestion": f"Extract `{name}` into a shared `utils/` module to eliminate duplication.",
                "severity": "medium",
            })

    if has_fat_controller:
        suggestions.append({
            "file": "",
            "pattern_name": "Service Layer Pattern",
            "description": "Route handlers / controllers contain substantial logic (>200 lines).",
            "suggestion": "Extract business logic into a `services/` layer. Controllers should only parse requests and delegate.",
            "severity": "high",
        })

    if has_scattered_queries:
        suggestions.append({
            "file": "",
            "pattern_name": "Repository Pattern",
            "description": "Database queries found outside dedicated data access files.",
            "suggestion": "Centralize database operations into a `repositories/` or `models/` layer.",
            "severity": "medium",
        })

    if has_many_params:
        suggestions.append({
            "file": "",
            "pattern_name": "Configuration Object Pattern",
            "description": "Functions with >5 parameters detected across the codebase.",
            "suggestion": "Group related parameters into config objects, dataclasses, or TypeScript interfaces.",
            "severity": "medium",
        })

    # React custom hook extraction opportunities
    duplicated_hooks = {k: v for k, v in react_hook_patterns.items() if len(set(v)) > 1}
    if duplicated_hooks:
        suggestions.append({
            "file": "",
            "pattern_name": "Custom Hook Extraction (React)",
            "description": f"Similar useState+useEffect patterns found in {len(duplicated_hooks)} component groups.",
            "suggestion": "Extract shared stateful logic into custom hooks (`useXxx`) to follow DRY.",
            "severity": "medium",
        })

    return suggestions


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

class StructureAnalyzerInput(BaseModel):
    """Input schema for the structure analyzer tool."""

    repo_path: str = Field(
        ...,
        description="Absolute path to the repository root to analyze.",
    )
    priority_files: list[str] = Field(
        default=[],
        description="List of relative file paths that the audit is focused on.",
    )


@tool(args_schema=StructureAnalyzerInput)
def analyze_project_structure(repo_path: str, priority_files: list[str] | None = None) -> str:
    """Analyze a repository's project structure, detect frameworks, and suggest
    design patterns and folder organization improvements.

    Detects the project's tech stack (React, Express, Django, etc.),
    compares the folder layout against community best practices,
    and identifies opportunities for design patterns that reduce complexity
    (Service Layer, Repository, Strategy, Custom Hooks, Utility Extraction).

    Args:
        repo_path: Absolute path to the repository root.
        priority_files: Optional list of files the audit is focused on.

    Returns:
        JSON string with framework detection, structure recommendations,
        and design pattern suggestions.

    Raises:
        FileNotFoundError: If the repository path does not exist.
    """
    root = Path(repo_path)
    if not root.exists():
        return json.dumps({"error": f"Repo path not found: {repo_path}"})

    # Detect frameworks
    frameworks = _detect_framework(root)

    # Analyze folder structure
    structure = _analyze_folder_structure(root, frameworks)

    # Detect design pattern opportunities
    pattern_suggestions = _detect_pattern_opportunities(root, priority_files or [])

    # Build findings for the agent
    findings: list[dict] = []

    # Structure findings
    for rec in structure.get("recommendations", []):
        findings.append({
            "category": "project_structure",
            "severity": rec["severity"],
            "description": f"[{rec['type']}] {rec.get('purpose', rec.get('folder', ''))}",
            "suggestion": f"Create `{rec['folder']}` — {rec.get('purpose', 'standard folder for this framework')}.",
            "file": rec["folder"],
        })

    # Design pattern findings
    for ps in pattern_suggestions:
        findings.append({
            "category": "design_pattern",
            "severity": ps["severity"],
            "description": f"[{ps['pattern_name']}] {ps['description']}",
            "suggestion": ps["suggestion"],
            "file": ps.get("file", ""),
        })

    return json.dumps({
        "status": "success",
        "detected_frameworks": frameworks,
        "structure_analysis": {
            "total_directories": structure["total_directories"],
            "file_extensions": structure["file_extensions"],
            "top_directories_by_file_count": structure["files_per_dir_top"],
        },
        "missing_recommended_dirs": structure["missing_recommended_dirs"],
        "total_findings": len(findings),
        "findings": findings,
    }, indent=2)
