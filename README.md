# 🛡️ CodeSentinel — Intelligent Codebase Audit & Refactoring MAS

A locally-hosted **Multi-Agent System (MAS)** that performs deep, multi-dimensional code audits on any local Git repository. Built with **LangGraph** for orchestration and **Ollama** SLMs as the LLM engine. No cloud APIs. No paid keys. Everything runs locally.

> **SLIIT SE4010 — CTSE Assignment 2**

---

## 🏗️ Architecture

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

### Agent → Model Mapping

| Agent | Ollama Model | Role |
|-------|-------------|------|
| Orchestrator/Planner | `llama3:8b` | Planning, delegation, merging, conflict resolution |
| Code Quality Agent | `deepseek-coder-v2:16b` | AST analysis, complexity metrics, code smell detection |
| Security Vulnerability Agent | `llama3:8b` | Pattern-based vuln scanning, CWE classification |
| Refactoring Agent | `deepseek-coder-v2:16b` | Prioritized fix suggestions with before/after code |

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| Orchestration | LangGraph |
| LLM Runtime | Ollama (local) |
| Language | Python 3.11+ |
| MCP Server | `@modelcontextprotocol/server-sqlite` |
| State Store | SQLite |
| AST Parsing | Python `ast` stdlib |
| Web API | FastAPI + Uvicorn |
| Frontend | React + Vite |
| Testing | pytest + LLM-as-a-Judge |
| Observability | Custom JSON tracer |

---

## 📁 Project Structure

```
codesentinel/
├── src/
│   ├── main.py                    # CLI entry point (--repo, --api)
│   ├── graph.py                   # LangGraph workflow definition
│   ├── state.py                   # TypedDict global state schema
│   ├── config.py                  # Models, paths, thresholds
│   ├── api.py                     # FastAPI backend for React UI
│   ├── agents/
│   │   ├── orchestrator.py        # Planning + merge agent
│   │   ├── code_quality.py        # Code quality analysis agent
│   │   ├── security.py            # Security vulnerability agent
│   │   └── refactoring.py         # Refactoring suggestions agent
│   ├── tools/
│   │   ├── ast_parser.py          # Python AST analysis tool
│   │   ├── git_analyzer.py        # Git history/blame/diff tool
│   │   ├── pattern_scanner.py     # Regex-based vulnerability scanner
│   │   └── report_generator.py    # Markdown report builder
│   ├── mcp/
│   │   └── sqlite_client.py       # SQLite MCP server client
│   ├── db/
│   │   ├── schema.sql             # Database schema (4 tables)
│   │   └── queries.py             # Parameterized CRUD functions
│   └── observability/
│       └── tracer.py              # JSON execution tracer
├── tests/
│   ├── conftest.py                # Shared fixtures (sample repos)
│   ├── test_tools.py              # Unit tests for all tools
│   ├── test_orchestrator.py       # Orchestrator evaluation
│   ├── test_code_quality.py       # Code Quality agent tests
│   ├── test_security.py           # Security agent tests
│   ├── test_refactoring.py        # Refactoring agent tests
│   ├── test_integration.py        # End-to-end pipeline tests
│   └── llm_judge.py              # LLM-as-a-Judge harness
├── frontend/
│   ├── src/App.jsx                # React UI (GitHub dark theme)
│   ├── src/main.jsx               # React entry point
│   ├── index.html                 # HTML template
│   ├── vite.config.js             # Vite config with API proxy
│   └── package.json               # Node.js dependencies
├── data/                          # SQLite database (auto-created)
├── reports/                       # Generated audit reports
├── logs/                          # Execution trace logs
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.11+**
- **Node.js 18+** (for frontend)
- **Git** (for git_analyzer tool)
- **Ollama** (for local LLM inference)

### 1. Install Ollama and Pull Models

```bash
# Install Ollama from https://ollama.ai
ollama pull llama3:8b
ollama pull deepseek-coder-v2:16b
```

### 2. Install MCP SQLite Server

```bash
npx -y @modelcontextprotocol/server-sqlite data/codesentinel.db
```

### 3. Python Environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 4. Initialize Database

```bash
python -c "from src.db.queries import init_db; init_db()"
```

### 5. Run an Audit (CLI Mode)

```bash
python -m src.main --repo /path/to/target/repo
```

### 6. Run with Web UI

```bash
# Terminal 1: Start the API server
python -m src.main --repo /path/to/any/repo --api --port 8000

# Terminal 2: Start the React frontend
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 in your browser.

---

## 💻 Usage

### CLI Mode

```bash
# Basic audit
python -m src.main --repo /path/to/repo

# Start with web API
python -m src.main --repo /path/to/repo --api --port 8000
```

### What It Does

1. **Orchestrator** analyzes the repo (language, framework, git history), builds an audit plan
2. **Code Quality Agent** parses ASTs, calculates complexity, detects code smells
3. **Security Agent** scans for hardcoded secrets, SQL injection, command injection, path traversal
4. **Orchestrator** merges and deduplicates findings, generates a report
5. **Refactoring Agent** produces a prioritized fix plan with before/after code

### Output

- **Markdown report** in `reports/` directory
- **JSON trace logs** in `logs/` directory
- **SQLite database** in `data/codesentinel.db` with full history

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test suite
python -m pytest tests/test_tools.py -v
python -m pytest tests/test_security.py -v

# Run integration tests
python -m pytest tests/test_integration.py -v
```

### LLM-as-a-Judge Evaluation

```python
from tests.llm_judge import run_full_evaluation

# After running an audit:
result = run_full_evaluation(final_state)
print(f"Overall Score: {result['overall_score']}")
print(f"All Pass: {result['all_pass']}")
```

---

## 🔍 Custom Tools

| Tool | Description | Agent |
|------|-------------|-------|
| `parse_ast_tool` | Python AST analysis — functions, classes, complexity, nesting | Code Quality |
| `git_analyzer` | Git repo info, recent changes, blame, history search | Orchestrator |
| `pattern_scanner` | Regex-based vulnerability scanning (5 categories, CWE IDs) | Security |
| `generate_report` | Markdown report generation with executive summary | Orchestrator |
| `sqlite_query` | Parameterized SQLite queries via MCP | All agents |

---

## 📊 Detected Issue Categories

### Code Quality
- Long functions (>50 lines)
- Deep nesting (>3 levels)
- High cyclomatic complexity (>10)
- God classes (>10 methods)
- Bare except clauses
- Unused imports

### Security Vulnerabilities
- Hardcoded secrets/credentials (CWE-798)
- SQL injection via f-strings/.format() (CWE-89)
- Command injection via os.system/subprocess (CWE-78)
- Path traversal (CWE-22)
- Insecure deserialization via pickle (CWE-502)

---

## 🌐 Web UI

The React frontend provides a GitHub-themed dark mode interface with:

- **Repository input** — enter any local Git repo path
- **Live workflow tracking** — see each agent step execute in real-time
- **Findings browser** — code quality, security, and refactoring tabs
- **Summary cards** — total findings, critical count, refactoring actions
- **Expandable details** — file locations, suggestions, CWE references

---

## 📝 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/audit/start` | Start a new audit pipeline |
| GET | `/api/audit/{id}/status` | Poll audit status and results |
| GET | `/api/audit/{id}/stream` | SSE stream for real-time progress |
| GET | `/api/findings/{run_id}` | Get findings for a completed run |
| GET | `/api/history` | List previous audit runs |
| GET | `/api/health` | Health check |

---

## 👥 Team Contributions

Each team member built one agent and one custom tool:

| Member | Agent | Tool |
|--------|-------|------|
| Member 1 | Orchestrator Agent | `git_analyzer` |
| Member 2 | Code Quality Agent | `parse_ast_tool` |
| Member 3 | Security Agent | `pattern_scanner` |
| Member 4 | Refactoring Agent | `report_generator` |

---

## ⚠️ Important Notes

- **100% Local** — No cloud API calls. All LLM inference via Ollama.
- **Deterministic First** — Agents do AST/regex analysis first, LLM enhances optionally.
- **Graceful Degradation** — Works even if Ollama models aren't running (tools still produce findings).
- **Parameterized Queries** — All SQL uses parameterized statements (no injection risk).

---

## 📄 License

This project is developed for academic purposes as part of the SLIIT SE4010 — CTSE module.
