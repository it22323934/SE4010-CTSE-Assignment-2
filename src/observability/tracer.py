"""Custom JSON execution tracer for CodeSentinel observability.

Records all agent inputs, tool calls, outputs, and timing into structured
JSON log files for debugging and evaluation.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from src.config import LOGS_DIR


class ExecutionTracer:
    """Traces agent execution and persists to JSON log files.

    Each audit run gets its own log file with structured entries for
    every agent invocation, tool call, and state mutation.

    Attributes:
        run_id: The current audit run identifier.
        log_path: Path to the log file for this run.
        entries: In-memory list of trace entries.
    """

    def __init__(self, run_id: int) -> None:
        """Initialize the tracer for a specific audit run.

        Args:
            run_id: The audit run identifier.
        """
        self.run_id = run_id
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = LOGS_DIR / f"trace_{run_id}_{timestamp}.json"
        self.entries: list[dict[str, Any]] = []
        self._start_times: dict[str, float] = {}

    def start_agent(self, agent_name: str, input_summary: str) -> None:
        """Record the start of an agent execution.

        Args:
            agent_name: Name of the agent starting.
            input_summary: Brief description of the agent's input.
        """
        self._start_times[agent_name] = time.time()
        self.entries.append({
            "event": "agent_start",
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "input_summary": input_summary,
        })

    def log_tool_call(self, agent_name: str, tool_name: str, params: dict, result_summary: str) -> None:
        """Record a tool call made by an agent.

        Args:
            agent_name: Name of the calling agent.
            tool_name: Name of the tool invoked.
            params: Parameters passed to the tool.
            result_summary: Brief description of the tool's output.
        """
        self.entries.append({
            "event": "tool_call",
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "params": params,
            "result_summary": result_summary,
        })

    def log_llm_call(self, agent_name: str, model: str, prompt_summary: str, response_summary: str) -> None:
        """Record an LLM invocation by an agent.

        Args:
            agent_name: Name of the calling agent.
            model: Model identifier used.
            prompt_summary: Brief description of the prompt.
            response_summary: Brief description of the response.
        """
        self.entries.append({
            "event": "llm_call",
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "prompt_summary": prompt_summary,
            "response_summary": response_summary,
        })

    def end_agent(self, agent_name: str, output_summary: str, error: str | None = None) -> dict:
        """Record the end of an agent execution and return a trace entry.

        Args:
            agent_name: Name of the agent finishing.
            output_summary: Brief description of the agent's output.
            error: Error message if the agent failed.

        Returns:
            AgentTrace-compatible dict for state storage.
        """
        start_time = self._start_times.pop(agent_name, time.time())
        duration_ms = int((time.time() - start_time) * 1000)

        # Collect tool calls for this agent
        tool_calls = [
            e for e in self.entries
            if e.get("agent") == agent_name and e.get("event") == "tool_call"
        ]

        trace_entry = {
            "event": "agent_end",
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "output_summary": output_summary,
            "duration_ms": duration_ms,
            "error": error,
        }
        self.entries.append(trace_entry)

        # Return state-compatible AgentTrace
        return {
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "tool_calls": [{"tool": t["tool"], "params": t.get("params", {})} for t in tool_calls],
            "input_summary": next(
                (e["input_summary"] for e in self.entries if e.get("agent") == agent_name and e.get("event") == "agent_start"),
                "",
            ),
            "output_summary": output_summary,
            "duration_ms": duration_ms,
            "error": error,
        }

    def log_error(self, agent_name: str, error: str) -> None:
        """Record an error during execution.

        Args:
            agent_name: Name of the agent encountering the error.
            error: Error description.
        """
        self.entries.append({
            "event": "error",
            "agent": agent_name,
            "timestamp": datetime.now().isoformat(),
            "error": error,
        })

    def save(self) -> Path:
        """Persist all trace entries to the JSON log file.

        Returns:
            Path to the saved log file.
        """
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(
            json.dumps(
                {
                    "run_id": self.run_id,
                    "total_entries": len(self.entries),
                    "entries": self.entries,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return self.log_path


# Global tracer instance — initialized per run
_tracer: ExecutionTracer | None = None


def init_tracer(run_id: int) -> ExecutionTracer:
    """Initialize the global tracer for an audit run.

    Args:
        run_id: The audit run identifier.

    Returns:
        The initialized ExecutionTracer instance.
    """
    global _tracer
    _tracer = ExecutionTracer(run_id)
    return _tracer


def get_tracer() -> ExecutionTracer:
    """Get the current global tracer instance.

    Returns:
        The active ExecutionTracer.

    Raises:
        RuntimeError: If the tracer has not been initialized.
    """
    if _tracer is None:
        raise RuntimeError("Tracer not initialized. Call init_tracer(run_id) first.")
    return _tracer
