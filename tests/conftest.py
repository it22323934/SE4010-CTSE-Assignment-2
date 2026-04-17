"""Shared pytest fixtures for CodeSentinel tests.

Provides:
- Temporary sample repositories with vulnerable, messy, and clean Python files
- Isolated SQLite database for tests
- Mock state objects
- Tracer initialization
"""

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import pytest

from src.config import DB_PATH
from src.db.queries import init_db
from src.observability.tracer import init_tracer


# --- Sample Python Files ---

VULNERABLE_PY = '''\
"""A deliberately vulnerable Python file for testing."""
import os
import pickle

API_KEY = "sk-12345678901234567890abcdef"
DB_PASSWORD = "SuperSecret123!"

def get_user(user_id):
    """Get user by ID — SQL injection vulnerable."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def run_command(cmd):
    """Run a shell command — command injection vulnerable."""
    os.system(cmd)

def load_data(raw_bytes):
    """Load pickled data — insecure deserialization."""
    return pickle.loads(raw_bytes)

def read_file(filename):
    """Read a file — path traversal vulnerable."""
    path = "/var/data/" + filename
    with open(path) as f:
        return f.read()
'''

MESSY_PY = '''\
"""A messy Python file with code quality issues."""
import os
import sys
import json
import re
import math

# Unused imports: re, math

class GodObject:
    """A class that does too many things."""
    def __init__(self):
        self.data = []
        self.cache = {}
        self.config = {}
        self.state = None
    def method_a(self): pass
    def method_b(self): pass
    def method_c(self): pass
    def method_d(self): pass
    def method_e(self): pass
    def method_f(self): pass
    def method_g(self): pass
    def method_h(self): pass
    def method_i(self): pass
    def method_j(self): pass
    def method_k(self): pass

def deeply_nested(x):
    """Deeply nested function."""
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                for j in range(i):
                    if j > 5:
                        return j
    return None

def long_function():
    """A function that is way too long."""
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    h = 8
    i = 9
    j = 10
    k = 11
    l = 12
    m = 13
    n = 14
    o = 15
    p = 16
    q = 17
    r = 18
    s = 19
    t = 20
    u = 21
    v = 22
    w = 23
    x = 24
    y = 25
    z = 26
    aa = 27
    bb = 28
    cc = 29
    dd = 30
    ee = 31
    ff = 32
    gg = 33
    hh = 34
    ii = 35
    jj = 36
    kk = 37
    ll = 38
    mm = 39
    nn = 40
    oo = 41
    pp = 42
    qq = 43
    rr = 44
    ss = 45
    tt = 46
    uu = 47
    vv = 48
    ww = 49
    xx = 50
    yy = 51
    zz = 52
    return zz

def bare_except_example():
    """Uses bare except."""
    try:
        risky()
    except:
        pass
'''

CLEAN_PY = '''\
"""A clean Python file with no issues."""
from pathlib import Path

BASE_DIR = Path(".")


def greet(name: str) -> str:
    """Return a greeting message.

    Args:
        name: The name to greet.

    Returns:
        A greeting string.
    """
    return f"Hello, {name}!"


def add(a: int, b: int) -> int:
    """Add two numbers.

    Args:
        a: First number.
        b: Second number.

    Returns:
        Sum of a and b.
    """
    return a + b
'''


@pytest.fixture(scope="session")
def sample_repo(tmp_path_factory) -> Path:
    """Create a temporary Git repository with sample files.

    Returns:
        Path to the temporary repository root.
    """
    repo_dir = tmp_path_factory.mktemp("sample_repo")

    # Write sample files
    (repo_dir / "vulnerable.py").write_text(VULNERABLE_PY, encoding="utf-8")
    (repo_dir / "messy.py").write_text(MESSY_PY, encoding="utf-8")
    (repo_dir / "clean.py").write_text(CLEAN_PY, encoding="utf-8")

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, capture_output=True)

    return repo_dir


@pytest.fixture(scope="session")
def test_db(tmp_path_factory) -> Path:
    """Create an isolated test database.

    Returns:
        Path to the temporary database file.
    """
    import src.config as config

    db_dir = tmp_path_factory.mktemp("test_db")
    test_db_path = db_dir / "test_codesentinel.db"

    # Temporarily override DB_PATH for tests
    original_db = config.DB_PATH
    config.DB_PATH = test_db_path

    init_db()

    yield test_db_path

    # Restore
    config.DB_PATH = original_db


@pytest.fixture(autouse=True)
def _init_tracer():
    """Auto-initialize tracer for all tests."""
    init_tracer(run_id=0)


@pytest.fixture
def mock_audit_plan() -> dict:
    """Return a mock audit plan for testing."""
    return {
        "language": "python",
        "framework": "none",
        "total_files": 3,
        "priority_files": ["vulnerable.py", "messy.py", "clean.py"],
        "prioritization_reason": "Test fixture",
        "run_code_quality": True,
        "run_security": True,
        "previous_audit_exists": False,
        "previous_run_id": None,
        "notes": "Test audit plan",
    }


@pytest.fixture
def mock_findings() -> list[dict]:
    """Return mock findings for testing."""
    return [
        {
            "id": "CQ-001",
            "file": "messy.py",
            "line_start": 60,
            "line_end": 112,
            "category": "long_function",
            "agent_source": "code_quality",
            "severity": "medium",
            "cwe_id": None,
            "description": "Function 'long_function' is too long (52 lines > 50 max)",
            "suggestion": "Break into smaller functions",
            "confidence": 1.0,
            "is_new": True,
        },
        {
            "id": "SEC-001",
            "file": "vulnerable.py",
            "line_start": 5,
            "line_end": 5,
            "category": "hardcoded_secret",
            "agent_source": "security",
            "severity": "critical",
            "cwe_id": "CWE-798",
            "description": "Hardcoded API key found",
            "suggestion": "Use environment variables",
            "confidence": 0.95,
            "is_new": True,
        },
        {
            "id": "SEC-002",
            "file": "vulnerable.py",
            "line_start": 10,
            "line_end": 10,
            "category": "sql_injection",
            "agent_source": "security",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "description": "SQL query uses f-string interpolation",
            "suggestion": "Use parameterized queries",
            "confidence": 0.9,
            "is_new": True,
        },
    ]
