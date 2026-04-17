"""SQLite MCP server interaction layer for CodeSentinel.

Provides both MCP-based and native SQLite tool access for agents.
Falls back to native Python sqlite3 if MCP server is unavailable.
"""

import json
import sqlite3
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field

import src.config as _config


class SQLiteQueryInput(BaseModel):
    """Input schema for SQLite query execution."""

    query: str = Field(
        ...,
        description="SQL query to execute. For reads, use SELECT. For writes, use INSERT/UPDATE.",
    )
    params: list[str] = Field(
        default_factory=list,
        description="Parameterized query values to prevent SQL injection.",
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
    - findings: id, run_id, file_path, line_start, line_end, category, severity, description
    - file_metrics: id, run_id, file_path, total_lines, complexity_avg, functions_count
    - refactoring_actions: id, run_id, priority, title, file_path, before_code, after_code

    Args:
        query: SQL statement to execute.
        params: Optional list of parameters for parameterized queries.

    Returns:
        JSON with query results or confirmation of write operation.

    Raises:
        sqlite3.Error: If the SQL query is malformed.
    """
    try:
        conn = sqlite3.connect(_config.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        if query.strip().upper().startswith("SELECT"):
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return json.dumps(
                {"status": "success", "data": rows, "count": len(rows)},
                indent=2,
                default=str,
            )
        else:
            conn.commit()
            affected = cursor.rowcount
            conn.close()
            return json.dumps({"status": "success", "rows_affected": affected})

    except sqlite3.Error as e:
        return json.dumps({"status": "error", "error": f"SQLite error: {e}", "tool": "sqlite_query"})
    except Exception as e:
        return json.dumps({"status": "error", "error": f"{type(e).__name__}: {e}", "tool": "sqlite_query"})


async def get_mcp_tools() -> list:
    """Initialize MCP client and return SQLite tools.

    Attempts to connect to the MCP SQLite server via stdio.
    Falls back gracefully if the MCP server is not available.

    Returns:
        List of LangChain tools wrapping the MCP SQLite server's capabilities.
    """
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient

        client = MultiServerMCPClient(
            {
                "sqlite": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-sqlite",
                        str(DB_PATH),
                    ],
                    "transport": "stdio",
                }
            }
        )
        tools = await client.get_tools()
        return tools
    except ImportError:
        # langchain-mcp-adapters not installed, return native tool
        return [sqlite_query]
    except Exception:
        # MCP server not available, return native tool
        return [sqlite_query]
