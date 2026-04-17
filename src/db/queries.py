"""Reusable database query functions for CodeSentinel.

Provides typed functions for all CRUD operations against the audit database.
All queries use parameterized statements to prevent SQL injection.
"""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path

import src.config as config


def get_connection() -> sqlite3.Connection:
    """Get a SQLite connection with row factory enabled.

    Returns:
        A sqlite3.Connection configured to return Row objects.
    """
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the database schema from schema.sql.

    Creates all tables and indexes if they don't already exist.
    Safe to call multiple times (uses IF NOT EXISTS).
    """
    schema_path = Path(__file__).parent / "schema.sql"
    schema_sql = schema_path.read_text(encoding="utf-8")

    conn = get_connection()
    conn.executescript(schema_sql)
    conn.close()


def generate_finding_uid(file_path: str, line_start: int, category: str) -> str:
    """Generate a stable unique ID for a finding.

    Enables cross-run tracking: detect new, fixed, and persistent findings.

    Args:
        file_path: Path to the file containing the finding.
        line_start: Starting line number.
        category: Finding category (e.g., "sql_injection").

    Returns:
        SHA256 hash prefix (16 chars) as stable identifier.
    """
    raw = f"{file_path}:{line_start}:{category}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def create_audit_run(
    repo_path: str,
    repo_name: str,
    commit_hash: str,
    branch: str = "main",
    language: str | None = None,
    framework: str | None = None,
) -> int:
    """Create a new audit run record and return its ID.

    Args:
        repo_path: Absolute path to the repository.
        repo_name: Short name of the repository.
        commit_hash: Current HEAD commit hash.
        branch: Current branch name.
        language: Detected primary language.
        framework: Detected framework.

    Returns:
        The auto-incremented run_id.
    """
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO audit_runs (repo_path, repo_name, commit_hash, branch, language, framework)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (repo_path, repo_name, commit_hash, branch, language, framework),
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return run_id  # type: ignore[return-value]


def update_audit_run_status(run_id: int, status: str, summary: dict | None = None) -> None:
    """Update an audit run's status and optionally its summary.

    Args:
        run_id: The audit run to update.
        status: New status ('running', 'completed', 'failed').
        summary: Optional summary dict to serialize as JSON.
    """
    conn = get_connection()
    if summary:
        conn.execute(
            "UPDATE audit_runs SET status = ?, summary_json = ? WHERE id = ?",
            (status, json.dumps(summary), run_id),
        )
    else:
        conn.execute("UPDATE audit_runs SET status = ? WHERE id = ?", (status, run_id))
    conn.commit()
    conn.close()


def update_audit_run_counts(run_id: int, findings: list[dict]) -> None:
    """Update finding counts on an audit run based on final findings list.

    Args:
        run_id: The audit run to update.
        findings: List of finding dicts with 'severity' keys.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    conn = get_connection()
    conn.execute(
        """UPDATE audit_runs
           SET total_findings = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ?
           WHERE id = ?""",
        (len(findings), counts["critical"], counts["high"], counts["medium"], counts["low"], run_id),
    )
    conn.commit()
    conn.close()


def insert_finding(run_id: int, finding: dict) -> int:
    """Insert a single finding and return its database ID.

    Args:
        run_id: The parent audit run ID.
        finding: Finding dict with file, line_start, category, etc.

    Returns:
        The auto-incremented finding ID.
    """
    uid = generate_finding_uid(
        finding.get("file", ""),
        finding.get("line_start", 0),
        finding.get("category", ""),
    )

    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO findings
           (run_id, finding_uid, file_path, line_start, line_end, category,
            agent_source, severity, cwe_id, description, suggestion, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id,
            uid,
            finding.get("file", ""),
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            finding.get("category", ""),
            finding.get("agent_source", ""),
            finding.get("severity", "low"),
            finding.get("cwe_id"),
            finding.get("description", ""),
            finding.get("suggestion"),
            finding.get("confidence", 0.5),
        ),
    )
    finding_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return finding_id  # type: ignore[return-value]


def insert_findings_batch(run_id: int, findings: list[dict]) -> list[int]:
    """Insert multiple findings in a single transaction.

    Args:
        run_id: The parent audit run ID.
        findings: List of finding dicts.

    Returns:
        List of inserted finding IDs.
    """
    ids = []
    conn = get_connection()
    for finding in findings:
        uid = generate_finding_uid(
            finding.get("file", ""),
            finding.get("line_start", 0),
            finding.get("category", ""),
        )
        cursor = conn.execute(
            """INSERT INTO findings
               (run_id, finding_uid, file_path, line_start, line_end, category,
                agent_source, severity, cwe_id, description, suggestion, confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                uid,
                finding.get("file", ""),
                finding.get("line_start", 0),
                finding.get("line_end", 0),
                finding.get("category", ""),
                finding.get("agent_source", ""),
                finding.get("severity", "low"),
                finding.get("cwe_id"),
                finding.get("description", ""),
                finding.get("suggestion"),
                finding.get("confidence", 0.5),
            ),
        )
        ids.append(cursor.lastrowid)  # type: ignore[arg-type]
    conn.commit()
    conn.close()
    return ids


def insert_refactoring_action(run_id: int, action: dict) -> int:
    """Insert a refactoring action record.

    Args:
        run_id: The parent audit run ID.
        action: Refactoring action dict.

    Returns:
        The auto-incremented action ID.
    """
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO refactoring_actions
           (run_id, priority, title, file_path, before_code, after_code, rationale, depends_on)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id,
            action.get("priority", 0),
            action.get("title", ""),
            action.get("file", ""),
            action.get("before", ""),
            action.get("after", ""),
            action.get("rationale", ""),
            json.dumps(action.get("depends_on", [])),
        ),
    )
    action_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return action_id  # type: ignore[return-value]


def get_previous_runs(repo_path: str, limit: int = 5) -> list[dict]:
    """Get previous audit runs for a repository.

    Args:
        repo_path: Repository path to search for.
        limit: Maximum number of runs to return.

    Returns:
        List of run dicts ordered by timestamp descending.
    """
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, commit_hash, timestamp, total_findings, critical_count, status
           FROM audit_runs
           WHERE repo_path = ?
           ORDER BY timestamp DESC
           LIMIT ?""",
        (repo_path, limit),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_findings_for_run(run_id: int) -> list[dict]:
    """Get all findings for a specific audit run.

    Args:
        run_id: The audit run ID to query.

    Returns:
        List of finding dicts.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM findings WHERE run_id = ? ORDER BY severity, file_path",
        (run_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_file_metrics(run_id: int, metrics: dict) -> None:
    """Insert file metrics for a single file.

    Args:
        run_id: The parent audit run ID.
        metrics: Dict with file_path, total_lines, etc.
    """
    conn = get_connection()
    conn.execute(
        """INSERT INTO file_metrics
           (run_id, file_path, total_lines, code_lines, blank_lines, comment_lines,
            functions_count, classes_count, complexity_avg, complexity_max, max_nesting)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id,
            metrics.get("file_path", ""),
            metrics.get("total_lines", 0),
            metrics.get("code_lines", 0),
            metrics.get("blank_lines", 0),
            metrics.get("comment_lines", 0),
            metrics.get("functions_count", 0),
            metrics.get("classes_count", 0),
            metrics.get("complexity_avg", 0.0),
            metrics.get("complexity_max", 0),
            metrics.get("max_nesting", 0),
        ),
    )
    conn.commit()
    conn.close()
