"""Configuration constants and model mappings for CodeSentinel.

Centralizes all configurable values: model names, paths, and runtime settings.
No hardcoded paths — everything is derived from project root or CLI args.
"""

from pathlib import Path

# --- Project Paths ---
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"
DB_PATH = DATA_DIR / "codesentinel.db"
CHECKPOINTS_DB = DATA_DIR / "checkpoints.db"
CLONED_REPOS_DIR = DATA_DIR / "cloned_repos"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
CLONED_REPOS_DIR.mkdir(exist_ok=True)

# --- Ollama Model Mapping ---
# Each agent uses a specific model as per assignment requirements
MODELS: dict[str, str] = {
    "orchestrator": "llama3:8b",
    "code_quality": "deepseek-coder-v2:16b",
    "security": "llama3:8b",
    "refactoring": "deepseek-coder-v2:16b",
}

# --- LLM Settings ---
LLM_SETTINGS: dict[str, dict] = {
    "orchestrator": {
        "temperature": 0.2,
        "num_predict": 4096,
    },
    "code_quality": {
        "temperature": 0.1,
        "num_predict": 4096,
    },
    "security": {
        "temperature": 0.1,
        "num_predict": 4096,
    },
    "refactoring": {
        "temperature": 0.3,
        "num_predict": 8192,
    },
}

# --- Audit Settings ---
MAX_PRIORITY_FILES = 20
MAX_FUNCTION_LENGTH = 50
MAX_NESTING_DEPTH = 3
MAX_CLASS_METHODS = 10
MAX_CLASS_LINES = 300
MAX_CYCLOMATIC_COMPLEXITY = 10
RECENT_COMMITS_WINDOW = 10

# --- Vulnerability Patterns ---
SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "java"}

# --- Ollama Base URL ---
OLLAMA_BASE_URL = "http://localhost:11434"
