# CodeSentinel — Intelligent Codebase Audit & Refactoring MAS

## Project Identity

**CodeSentinel** is a locally-hosted Multi-Agent System (MAS) that performs deep, multi-dimensional code audits on any local Git repository. It uses **LangGraph** for orchestration and **Ollama** SLMs as the LLM engine. No cloud APIs. No paid keys. Everything runs locally.

This is a university assignment (SLIIT SE4010 – CTSE) with strict architectural requirements — read them carefully before generating any code.

---

## Architecture Overview

```
User Input (repo path)
        │
        ▼
┌──────────────────────┐
│  Orchestrator Agent   │  (llama3:8b)
│  Plans audit, routes  │
│  findings, merges     │
│  conflicts            │
└──────┬───────────────┘
       │ delegates
       ├────────────────────────┐
       ▼                        ▼
┌──────────────┐    ┌───────────────────┐
│ Code Quality │    │ Security Vuln     │
│ Agent        │    │ Agent             │
│ (deepseek-   │    │ (llama3:8b)       │
│  coder-v2:   │    │                   │
│  16b)        │    │                   │
└──────┬───────┘    └──────┬────────────┘
       │                    │
       └────────┬───────────┘
                ▼
       ┌────────────────┐
       │ Refactoring    │
       │ Agent          │
       │ (deepseek-     │
       │  coder-v2:16b) │
       └────────┬───────┘
                │
                ▼
       ┌────────────────┐
       │ Final Report   │
       │ (Orchestrator) │
       └────────────────┘
```

### Agent ↔ Model Mapping

| Agent | Ollama Model | Why |
|-------|-------------|-----|
| Orchestrator/Planner | `llama3:8b` | Strong general reasoning, planning, and delegation |
| Code Quality Agent | `deepseek-coder-v2:16b` | Purpose-built for code understanding and structural analysis |
| Security Vulnerability Agent | `llama3:8b` | Good at pattern reasoning, classifying severity, explaining attack vectors |
| Refactoring Agent | `deepseek-coder-v2:16b` | Best at generating concrete code refactoring suggestions |

> **IMPORTANT**: Each agent MUST use a different model OR the same model with a distinctly different system prompt. The assignment requires demonstrating multi-agent design, not one model doing everything.

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Orchestration | LangGraph | latest |
| LLM Runtime | Ollama (local) | latest |
| Language | Python | 3.11+ |
| MCP Server | SQLite MCP (`mcp-server-sqlite`) | latest |
| State Store | SQLite | 3.x |
| AST Parsing | `tree-sitter` + `ast` (Python stdlib) | latest |
| Logging/Tracing | `langsmith` (local) or custom JSON logger | - |
| Testing | `pytest` + LLM-as-a-Judge | - |

---

## Project Structure

```
codesentinel/
├── .github/
│   ├── copilot-instructions.md          # THIS FILE
│   └── skills/
│       ├── langgraph-orchestration.md   # LangGraph patterns & workflow
│       ├── agent-design.md              # System prompts & persona design
│       ├── tool-development.md          # Custom tool conventions
│       ├── mcp-integration.md           # MCP server setup & usage
│       ├── state-management.md          # Global state schema & flow
│       └── testing-evaluation.md        # Testing harness & LLM-as-Judge
├── src/
│   ├── __init__.py
│   ├── main.py                          # Entry point — CLI interface
│   ├── graph.py                         # LangGraph workflow definition
│   ├── state.py                         # TypedDict state schema
│   ├── config.py                        # Model configs, paths, constants
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py              # Orchestrator/Planner agent node
│   │   ├── code_quality.py              # Code Quality agent node
│   │   ├── security.py                  # Security Vulnerability agent node
│   │   └── refactoring.py              # Refactoring agent node
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── ast_parser.py               # AST analysis tool
│   │   ├── git_analyzer.py             # Git history/blame/diff tool
│   │   ├── pattern_scanner.py          # Regex-based vulnerability scanner
│   │   └── report_generator.py         # Markdown report builder
│   ├── mcp/
│   │   ├── __init__.py
│   │   └── sqlite_client.py            # SQLite MCP server interaction layer
│   ├── db/
│   │   ├── __init__.py
│   │   ├── schema.sql                  # Database schema
│   │   └── queries.py                  # Reusable query functions
│   └── observability/
│       ├── __init__.py
│       └── tracer.py                   # Custom JSON execution tracer
├── tests/
│   ├── __init__.py
│   ├── conftest.py                     # Shared fixtures (sample repos, mock state)
│   ├── test_orchestrator.py            # Orchestrator evaluation
│   ├── test_code_quality.py            # Code Quality agent evaluation
│   ├── test_security.py               # Security agent evaluation
│   ├── test_refactoring.py            # Refactoring agent evaluation
│   ├── test_tools.py                  # Unit tests for all tools
│   ├── test_integration.py           # End-to-end pipeline test
│   └── llm_judge.py                   # LLM-as-a-Judge evaluation harness
├── data/
│   ├── sample_repos/                   # Git repos for testing/demo
│   └── codesentinel.db                # SQLite database (auto-created)
├── reports/                            # Generated audit reports
├── logs/                               # Execution trace logs
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Coding Conventions

### Python Standards
- **Python 3.11+** — use modern syntax (match/case, type unions with `|`)
- **Type hints on EVERYTHING** — function signatures, return types, variables where non-obvious
- **Docstrings on EVERYTHING** — Google-style docstrings with Args, Returns, Raises sections
- **No bare exceptions** — always catch specific exception types
- **f-strings** for string formatting, never `.format()` or `%`
- **Pydantic v2** for all data models and validation
- **pathlib.Path** instead of `os.path` everywhere

### Tool Development Rules
Every custom tool MUST follow this exact pattern:

```python
from langchain_core.tools import tool
from pydantic import BaseModel, Field

class MyToolInput(BaseModel):
    """Schema for MyTool input validation."""
    param: str = Field(..., description="Clear description of what this param does")

@tool(args_schema=MyToolInput)
def my_tool(param: str) -> str:
    """One-line summary of what this tool does.

    Detailed description of the tool's behavior, including edge cases
    and what the agent should expect as output.

    Args:
        param: Description of the parameter.

    Returns:
        A structured string or JSON describing the result.

    Raises:
        FileNotFoundError: If the target file does not exist.
        ValueError: If the input parameter is malformed.
    """
    try:
        # Implementation
        result = do_something(param)
        return json.dumps(result, indent=2)
    except SpecificError as e:
        return json.dumps({"error": str(e), "tool": "my_tool"})
```

### Agent Design Rules
- Every agent gets a `SYSTEM_PROMPT` constant at module top — never inline prompt strings
- System prompts must include: role, constraints, output format, what NOT to do
- Always bind tools to the agent model: `model.bind_tools([tool1, tool2])`
- Use structured output where possible (JSON mode)
- Never pass raw file contents to the LLM — always pre-process through tools first

### State Management Rules
- State is a `TypedDict` — defined ONCE in `src/state.py`
- Agents return state updates via `dict` — LangGraph merges them
- Use `Annotated[list, operator.add]` for list fields that accumulate across agents
- Never mutate state directly — always return a new dict from agent nodes

### Import Conventions
```python
# Standard library
import json
import subprocess
from pathlib import Path
from typing import Annotated, TypedDict

# Third-party
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

# Local
from src.state import AuditState
from src.tools.ast_parser import parse_ast
from src.config import MODELS, REPO_PATH
```

---

## Critical Assignment Requirements Checklist

Before submitting, verify ALL of these:

- [ ] **3-4 distinct agents** that interact with each other (not just sequential)
- [ ] **Custom Python tools** with strict type hinting and docstrings (one per student minimum)
- [ ] **State management** — global state flows between agents without context loss
- [ ] **Observability** — execution tracing/logging records inputs, tool calls, and outputs
- [ ] **Local only** — Ollama models, no OpenAI/Anthropic/cloud API calls
- [ ] **LangGraph** workflow with conditional edges (not just linear)
- [ ] **SQLite MCP** server integrated and used meaningfully
- [ ] **Testing** — automated evaluation script per agent + unified harness
- [ ] **Each student** built one agent AND one tool with proof of contribution
- [ ] **Demo video** ≤ 5 minutes showing full workflow
- [ ] **Technical report** 4-8 pages

---

## Git Workflow

- Branch naming: `feature/<agent-name>` or `feature/<tool-name>`
- Each student works on their agent/tool branch
- Merge to `develop` for integration testing
- `main` branch is always demo-ready
- Commit messages: `feat(agent): ...`, `feat(tool): ...`, `fix(state): ...`, `test(security): ...`

---

## Environment Setup

```bash
# 1. Install Ollama and pull models
ollama pull llama3:8b
ollama pull deepseek-coder-v2:16b

# 2. Install MCP SQLite server
npx -y @modelcontextprotocol/server-sqlite data/codesentinel.db

# 3. Python environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. Initialize database
python -c "from src.db import init_db; init_db()"

# 5. Run the system
python -m src.main --repo /path/to/target/repo
```

---

## What NOT To Do

- **DO NOT** use OpenAI, Anthropic, or any cloud LLM API
- **DO NOT** build a chatbot — this is an autonomous pipeline, not a conversation
- **DO NOT** hardcode file paths — use `config.py` and CLI arguments
- **DO NOT** pass entire files to the LLM — always pre-process through tools
- **DO NOT** skip error handling in tools — the assignment rubric penalizes this heavily
- **DO NOT** use `print()` for logging — use the structured tracer in `src/observability/`
- **DO NOT** let agents hallucinate tool outputs — if a tool fails, handle it gracefully