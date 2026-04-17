"""Tests for the vulnerability knowledge base (seed, query, pattern_scanner integration).

Tests the CWE/OWASP vulnerability pattern database, query functions,
and the pattern_scanner's ability to load patterns from the DB.
"""

import json
from pathlib import Path

import pytest

import src.config as config
from src.db.queries import (
    get_connection,
    get_pattern_categories,
    get_pattern_count,
    get_vulnerability_patterns,
    init_db,
)
from src.db.seed_vuln_patterns import VULN_PATTERNS, seed_vulnerability_patterns


@pytest.fixture
def seeded_db(tmp_path: Path):
    """Create a temporary DB with vulnerability patterns seeded.

    Yields:
        Path to the seeded database file.
    """
    original_db = config.DB_PATH
    test_db_path = tmp_path / "test_vuln_kb.db"
    config.DB_PATH = test_db_path

    init_db()
    seed_vulnerability_patterns()

    yield test_db_path

    config.DB_PATH = original_db


@pytest.fixture
def empty_db(tmp_path: Path):
    """Create a temporary DB with schema but no seeded patterns.

    Yields:
        Path to the empty database file.
    """
    original_db = config.DB_PATH
    test_db_path = tmp_path / "test_empty_kb.db"
    config.DB_PATH = test_db_path

    init_db()

    yield test_db_path

    config.DB_PATH = original_db


class TestSeedVulnPatterns:
    """Tests for the seed script and VULN_PATTERNS data."""

    def test_patterns_list_not_empty(self):
        """VULN_PATTERNS should contain 40+ entries."""
        assert len(VULN_PATTERNS) >= 40

    def test_all_patterns_have_required_fields(self):
        """Every pattern must have category, cwe_id, severity, pattern, description."""
        for i, p in enumerate(VULN_PATTERNS):
            assert "category" in p, f"Pattern {i} missing category"
            assert "cwe_id" in p, f"Pattern {i} missing cwe_id"
            assert "severity" in p, f"Pattern {i} missing severity"
            assert "pattern" in p, f"Pattern {i} missing pattern"
            assert "description" in p, f"Pattern {i} missing description"
            assert p["severity"] in ("critical", "high", "medium", "low"), (
                f"Pattern {i} has invalid severity: {p['severity']}"
            )

    def test_patterns_have_valid_cwe_format(self):
        """CWE IDs should match CWE-NNN format."""
        import re

        for p in VULN_PATTERNS:
            assert re.match(r"^CWE-\d+$", p["cwe_id"]), (
                f"Invalid CWE format: {p['cwe_id']}"
            )

    def test_seed_inserts_patterns(self, seeded_db: Path):
        """Seeding should populate the vulnerability_patterns table."""
        count = get_pattern_count()
        assert count == len(VULN_PATTERNS)

    def test_seed_is_idempotent(self, seeded_db: Path):
        """Running seed twice should not duplicate entries."""
        first_count = get_pattern_count()
        inserted = seed_vulnerability_patterns()
        second_count = get_pattern_count()

        assert inserted == 0
        assert second_count == first_count

    def test_seed_on_empty_db(self, empty_db: Path):
        """Seeding an empty DB should insert all patterns."""
        assert get_pattern_count() == 0
        count = seed_vulnerability_patterns()
        assert count == len(VULN_PATTERNS)


class TestVulnQueryFunctions:
    """Tests for vulnerability pattern query functions in queries.py."""

    def test_get_all_patterns(self, seeded_db: Path):
        """get_vulnerability_patterns() with no filters returns all."""
        patterns = get_vulnerability_patterns()
        assert len(patterns) == len(VULN_PATTERNS)

    def test_get_patterns_by_category(self, seeded_db: Path):
        """Filtering by category should return only matching patterns."""
        sql_patterns = get_vulnerability_patterns(category="sql_injection")
        assert len(sql_patterns) > 0
        for p in sql_patterns:
            assert p["category"] == "sql_injection"

    def test_get_patterns_by_severity(self, seeded_db: Path):
        """Filtering by severity should return only matching patterns."""
        critical = get_vulnerability_patterns(severity="critical")
        assert len(critical) > 0
        for p in critical:
            assert p["severity"] == "critical"

    def test_get_patterns_by_language(self, seeded_db: Path):
        """Language filter matches patterns that include the language."""
        py_patterns = get_vulnerability_patterns(language="python")
        assert len(py_patterns) > 0

    def test_get_patterns_combined_filters(self, seeded_db: Path):
        """Multiple filters should AND together."""
        results = get_vulnerability_patterns(
            category="sql_injection",
            severity="critical",
            language="python",
        )
        for p in results:
            assert p["category"] == "sql_injection"
            assert p["severity"] == "critical"
            assert "python" in p["languages"]

    def test_get_pattern_count(self, seeded_db: Path):
        """get_pattern_count() matches the seeded count."""
        assert get_pattern_count() == len(VULN_PATTERNS)

    def test_get_pattern_count_empty_db(self, empty_db: Path):
        """Empty DB should return 0."""
        assert get_pattern_count() == 0

    def test_get_pattern_categories(self, seeded_db: Path):
        """get_pattern_categories() returns category summaries."""
        categories = get_pattern_categories()
        assert len(categories) > 0

        cat_names = [c["category"] for c in categories]
        assert "sql_injection" in cat_names
        assert "hardcoded_secret" in cat_names

        for c in categories:
            assert "pattern_count" in c
            assert "cwe_ids" in c
            assert c["pattern_count"] > 0

    def test_nonexistent_category_returns_empty(self, seeded_db: Path):
        """Querying a category that doesn't exist returns empty list."""
        results = get_vulnerability_patterns(category="nonexistent_category")
        assert results == []


class TestPatternScannerWithDB:
    """Tests for pattern_scanner loading patterns from the vulnerability DB."""

    def test_scanner_uses_db_patterns_when_seeded(self, seeded_db: Path, tmp_path: Path):
        """pattern_scanner should use DB patterns when the DB is populated."""
        from src.tools.pattern_scanner import pattern_scanner

        vuln_file = tmp_path / "test_vuln.py"
        vuln_file.write_text(
            'import pickle\ndata = pickle.loads(raw_bytes)\n',
            encoding="utf-8",
        )

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vuln_file),
        }))

        assert result["status"] == "success"
        assert result["data"]["pattern_source"] == "database"
        assert result["data"]["total_patterns_loaded"] >= len(VULN_PATTERNS)

    def test_scanner_falls_back_to_static(self, empty_db: Path, tmp_path: Path):
        """pattern_scanner falls back to static patterns when DB is empty."""
        from src.tools.pattern_scanner import pattern_scanner

        vuln_file = tmp_path / "test_vuln2.py"
        vuln_file.write_text(
            'API_KEY = "sk-1234567890abcdef1234"\n',
            encoding="utf-8",
        )

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vuln_file),
        }))

        assert result["status"] == "success"
        assert result["data"]["pattern_source"] == "static_fallback"

    def test_db_patterns_detect_more_categories(self, seeded_db: Path, tmp_path: Path):
        """DB patterns should detect categories not in the static set (e.g., weak_crypto)."""
        from src.tools.pattern_scanner import pattern_scanner

        vuln_file = tmp_path / "crypto_vuln.py"
        vuln_file.write_text(
            'import hashlib\nhash_val = hashlib.md5(b"data")\n',
            encoding="utf-8",
        )

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vuln_file),
        }))

        assert result["status"] == "success"
        categories = [m["category"] for m in result["data"]["matches"]]
        assert "weak_crypto" in categories

    def test_db_patterns_include_owasp_ids(self, seeded_db: Path, tmp_path: Path):
        """DB-sourced matches should include OWASP IDs."""
        from src.tools.pattern_scanner import pattern_scanner

        vuln_file = tmp_path / "eval_vuln.py"
        vuln_file.write_text(
            'result = eval(user_input)\n',
            encoding="utf-8",
        )

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vuln_file),
        }))

        assert result["status"] == "success"
        matches = result["data"]["matches"]
        assert len(matches) > 0

        # At least one match should have owasp_id
        owasp_matches = [m for m in matches if m.get("owasp_id")]
        assert len(owasp_matches) > 0

    def test_db_patterns_include_remediation(self, seeded_db: Path, tmp_path: Path):
        """DB-sourced matches should include remediation guidance."""
        from src.tools.pattern_scanner import pattern_scanner

        vuln_file = tmp_path / "secret_vuln.py"
        vuln_file.write_text(
            'API_KEY = "AKIAIOSFODNN7EXAMPLE1"\n',
            encoding="utf-8",
        )

        result = json.loads(pattern_scanner.invoke({
            "file_path": str(vuln_file),
        }))

        assert result["status"] == "success"
        matches = result["data"]["matches"]
        assert len(matches) > 0

        # DB patterns include remediation guidance
        remediation_matches = [m for m in matches if m.get("remediation")]
        assert len(remediation_matches) > 0
