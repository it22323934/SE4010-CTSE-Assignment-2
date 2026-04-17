# Skill: MCP Integration for CodeSentinel

## Overview

CodeSentinel uses the **SQLite MCP Server** (`@modelcontextprotocol/server-sqlite`) to persist audit findings, track historical data across runs, and enable cross-run comparisons. This is NOT a bolted-on feature — it's a core architectural component that enables temporal analysis ("is this codebase getting better or worse?").

## MCP Server Setup

### Option A: Using `mcp-server-sqlite` (Official)

```bash
# Install the MCP server globally
npm install -g @modelcontextprotocol/server-sqlite

# Or run via npx (no install needed)
npx @modelcontextprotocol/server-sqlite data/codesentinel.db
```

### Option B: Using `langchain-mcp-adapters` (Recommended for LangGraph)

This is cleaner for Python integration — it wraps MCP servers as LangChain tools.

```bash
pip install langchain-mcp-adapters
```

```python
# src/mcp/sqlite_client.py

from langchain_mcp_adapters.client import MultiServerMCPClient

async def get_mcp_tools():
    """Initialize MCP client and return SQLite tools.

    Returns:
        List of LangChain tools wrapping the MCP SQLite server's capabilities
        (read_query, write_query, list_tables, describe_table, create_table).
    """
    client = MultiServerMCPClient(
        {
            "sqlite": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-sqlite",
                    "data/codesentinel.db"
                ],
                "transport": "stdio",
            }
        }
    )

    tools = await client.get_tools()
    return tools


# Alternative: Direct stdio connection
from langchain_mcp_adapters.client import MCPClient

async def get_sqlite_tools_direct():
    """Connect to SQLite MCP server via stdio."""
    client = MCPClient(
        transport="stdio",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-sqlite", "data/codesentinel.db"]
    )
    await client.connect()
    return client.get_tools()
```

### Option C: Native Python SQLite (Fallback)

If MCP setup causes issues, wrap SQLite operations as standard LangChain tools:

```python
# src/mcp/sqlite_native.py

import sqlite3
import json
from pathlib import Path
from langchain_core.tools import tool
from pydantic import BaseModel, Field

DB_PATH = Path("data/codesentinel.db")


class SQLiteQueryInput(BaseModel):
    """Input schema for SQLite query execution."""
    query: str = Field(
        ...,
        description="SQL query to execute. For reads, use SELECT. For writes, use INSERT/UPDATE."
    )
    params: list[str] = Field(
        default_factory=list,
        description="Parameterized query values to prevent SQL injection."
    )


@tool(args_schema=SQLiteQueryInput)
def sqlite_query(query: str, params: list[str] | None = None) -> str:
    """Execute a SQL query against the CodeSentinel audit database.

    Use this tool to:
    - Store new audit findings (INSERT INTO findings ...)
    - Retrieve previous audit results (SELECT FROM audit_runs ...)
    - Check historical trends (SELECT FROM file_metrics WHERE ...)
    - Update finding statuses (UPDATE findings SET status = ...)

    The database has these tables:
    - audit_runs: id, repo_path, commit_hash, timestamp, total_findings, summary_json
    - findings: id, run_id, file_path, line_start, line_end, category, severity, description, suggestion, status
    - file_metrics: id, run_id, file_path, total_lines, complexity_avg, functions_count, change_frequency

    Args:
        query: SQL statement to execute.
        params: Optional list of parameters for parameterized queries.

    Returns:
        JSON with query results or confirmation of write operation.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        if query.strip().upper().startswith("SELECT"):
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return json.dumps({"status": "success", "data": rows, "count": len(rows)}, indent=2)
        else:
            conn.commit()
            affected = cursor.rowcount
            conn.close()
            return json.dumps({"status": "success", "rows_affected": affected})

    except sqlite3.Error as e:
        return json.dumps({"status": "error", "error": f"SQLite error: {e}"})
    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}"})
```

## Database Schema

```sql
-- src/db/schema.sql

CREATE TABLE IF NOT EXISTS audit_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_path       TEXT NOT NULL,
    repo_name       TEXT NOT NULL,
    commit_hash     TEXT NOT NULL,
    branch          TEXT DEFAULT 'main',
    language        TEXT,
    framework       TEXT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'completed',  -- running | completed | failed
    summary_json    TEXT  -- Full summary blob for historical comparison
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL,
    finding_uid     TEXT NOT NULL,  -- Stable ID: hash(file + line + category) for cross-run dedup
    file_path       TEXT NOT NULL,
    line_start      INTEGER,
    line_end        INTEGER,
    category        TEXT NOT NULL,  -- sql_injection | long_function | hardcoded_secret | ...
    agent_source    TEXT NOT NULL,  -- code_quality | security | refactoring
    severity        TEXT NOT NULL,  -- critical | high | medium | low
    cwe_id          TEXT,           -- CWE-89, CWE-78, etc. (security only)
    description     TEXT NOT NULL,
    suggestion      TEXT,
    confidence      REAL DEFAULT 0.5,
    status          TEXT DEFAULT 'open',  -- open | fixed | wont_fix | false_positive
    first_seen_run  INTEGER,       -- Run ID when this finding was first detected
    FOREIGN KEY (run_id) REFERENCES audit_runs(id)
);

CREATE TABLE IF NOT EXISTS file_metrics (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL,
    file_path        TEXT NOT NULL,
    total_lines      INTEGER,
    code_lines       INTEGER,
    blank_lines      INTEGER,
    comment_lines    INTEGER,
    functions_count  INTEGER,
    classes_count    INTEGER,
    complexity_avg   REAL,
    complexity_max   INTEGER,
    max_nesting      INTEGER,
    change_frequency INTEGER DEFAULT 0,  -- Number of commits touching this file
    FOREIGN KEY (run_id) REFERENCES audit_runs(id)
);

CREATE TABLE IF NOT EXISTS refactoring_actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL,
    finding_id      INTEGER,
    priority        INTEGER NOT NULL,
    title           TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    before_code     TEXT,
    after_code      TEXT,
    rationale       TEXT,
    depends_on      TEXT,  -- JSON array of other refactoring action IDs
    status          TEXT DEFAULT 'pending',  -- pending | applied | skipped
    FOREIGN KEY (run_id) REFERENCES audit_runs(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_uid ON findings(finding_uid);
CREATE INDEX IF NOT EXISTS idx_metrics_run ON file_metrics(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_repo ON audit_runs(repo_path);
```

## How Agents Use the Database

### Orchestrator Agent — Query Previous Runs
```sql
-- Check if this repo has been audited before
SELECT id, commit_hash, timestamp, total_findings, critical_count
FROM audit_runs
WHERE repo_path = ?
ORDER BY timestamp DESC
LIMIT 5;

-- Get findings that have been open for multiple runs (persistent tech debt)
SELECT f.file_path, f.category, f.severity, f.description, COUNT(DISTINCT f.run_id) as seen_in_runs
FROM findings f
WHERE f.finding_uid IN (
    SELECT finding_uid FROM findings WHERE run_id = ?
)
GROUP BY f.finding_uid
HAVING seen_in_runs > 1
ORDER BY f.severity, seen_in_runs DESC;
```

### Security Agent — Store Findings
```sql
INSERT INTO findings (run_id, finding_uid, file_path, line_start, line_end, category, agent_source, severity, cwe_id, description, suggestion, confidence)
VALUES (?, ?, ?, ?, ?, 'sql_injection', 'security', 'critical', 'CWE-89', ?, ?, 0.95);
```

### Refactoring Agent — Store Refactoring Plan
```sql
INSERT INTO refactoring_actions (run_id, finding_id, priority, title, file_path, before_code, after_code, rationale, depends_on)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
```

## MCP in LangGraph — Wiring It Together

```python
# In graph.py or agent initialization

import asyncio
from src.mcp.sqlite_client import get_mcp_tools

async def initialize_agents():
    """Initialize all agents with their MCP tools."""
    mcp_tools = await get_mcp_tools()

    # Filter to only the tools each agent needs
    sqlite_read = [t for t in mcp_tools if t.name == "read_query"]
    sqlite_write = [t for t in mcp_tools if t.name in ("write_query", "create_table")]

    # Orchestrator gets read access for historical queries
    orchestrator_tools = sqlite_read + [git_analyzer]

    # Security and Code Quality get write access to store findings
    security_tools = sqlite_write + [pattern_scanner, git_analyzer]
    code_quality_tools = sqlite_write + [parse_ast_tool]

    # Refactoring gets both (read findings, write actions)
    refactoring_tools = sqlite_read + sqlite_write + [report_generator]

    return {
        "orchestrator": create_agent(MODELS["orchestrator"], orchestrator_tools),
        "security": create_agent(MODELS["security"], security_tools),
        "code_quality": create_agent(MODELS["code_quality"], code_quality_tools),
        "refactoring": create_agent(MODELS["refactoring"], refactoring_tools),
    }
```

## Cross-Run Comparison (What Makes This Advanced)

The `finding_uid` field enables tracking findings across runs:

```python
def generate_finding_uid(file_path: str, line_start: int, category: str) -> str:
    """Generate a stable unique ID for a finding.

    This allows the system to detect:
    - New findings (uid not in previous run)
    - Fixed findings (uid in previous run but not current)
    - Persistent findings (uid in both runs)

    Args:
        file_path: Path to the file containing the finding.
        line_start: Starting line number.
        category: Finding category (e.g., "sql_injection").

    Returns:
        SHA256 hash string used as stable identifier.
    """
    import hashlib
    raw = f"{file_path}:{line_start}:{category}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```