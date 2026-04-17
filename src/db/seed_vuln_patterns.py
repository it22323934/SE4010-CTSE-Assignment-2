"""Seed the vulnerability_patterns table with CWE Top 25 + OWASP patterns.

Run once after init_db() to populate the knowledge base.
Safe to run multiple times — skips insert if patterns already exist.

Usage:
    python -m src.db.seed_vuln_patterns
"""

import sqlite3

import src.config as config
from src.db.queries import get_connection, init_db

# ============================================================
# CWE Top 25 + OWASP Top 10 vulnerability patterns
# Each pattern targets Python code; language field can extend to JS/TS/Java
# ============================================================

VULN_PATTERNS: list[dict] = [
    # ──────────────────────────────────────────────────
    # CWE-79: Cross-Site Scripting (XSS)
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "xss",
        "subcategory": "reflected_xss",
        "cwe_id": "CWE-79",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""Markup\s*\(.*?(\+|\.format|{)""",
        "description": "Flask Markup() with dynamic content — potential XSS",
        "attack_vector": "Attacker injects <script> tags via user input rendered as safe HTML.",
        "remediation": "Use Jinja2 auto-escaping. Never mark user input as Markup().",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "xss",
        "subcategory": "template_injection",
        "cwe_id": "CWE-79",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""render_template_string\s*\(""",
        "description": "render_template_string() — server-side template injection risk",
        "attack_vector": "User-controlled input in template string allows arbitrary code execution.",
        "remediation": "Use render_template() with separate .html files instead.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "xss",
        "subcategory": "django_safe",
        "cwe_id": "CWE-79",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""mark_safe\s*\(""",
        "description": "Django mark_safe() with potentially untrusted content",
        "attack_vector": "Bypasses Django's auto-escaping, allowing XSS if input is user-controlled.",
        "remediation": "Sanitize input before marking safe, or use template filters.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-89: SQL Injection
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "sql_injection",
        "subcategory": "fstring_sql",
        "cwe_id": "CWE-89",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""f['"].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s.*?\{.*?\}.*?['"]""",
        "description": "SQL query with f-string interpolation — SQL injection vector",
        "attack_vector": "Attacker injects SQL via f-string variables to bypass authentication or extract data.",
        "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "sql_injection",
        "subcategory": "format_sql",
        "cwe_id": "CWE-89",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""['"].*?(SELECT|INSERT|UPDATE|DELETE|DROP)\s.*?['"].*?\.format\(""",
        "description": "SQL query using .format() — SQL injection vector",
        "attack_vector": "String formatting injects unsanitized user input into SQL statements.",
        "remediation": "Use parameterized queries or ORM methods instead of string formatting.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "sql_injection",
        "subcategory": "concat_sql",
        "cwe_id": "CWE-89",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""['"].*?(SELECT|INSERT|UPDATE|DELETE)\s.*?['"].*?\+\s*\w+""",
        "description": "SQL query with string concatenation — SQL injection vector",
        "attack_vector": "Concatenated user input allows SQL manipulation.",
        "remediation": "Use parameterized queries with placeholders.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "sql_injection",
        "subcategory": "percent_sql",
        "cwe_id": "CWE-89",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""['"].*?(SELECT|INSERT|UPDATE|DELETE)\s.*?%s.*?['"].*?%\s*\(""",
        "description": "SQL query using % string formatting — SQL injection risk",
        "attack_vector": "Old-style string formatting injects user input into SQL.",
        "remediation": "Use parameterized queries instead of % formatting.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-78: OS Command Injection
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "command_injection",
        "subcategory": "os_system",
        "cwe_id": "CWE-78",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""os\.system\s*\(.*?(\+|\.format|{)""",
        "description": "os.system() with dynamic input — command injection risk",
        "attack_vector": "Attacker injects shell commands via unsanitized input to os.system().",
        "remediation": "Use subprocess.run() with a list of arguments (no shell=True).",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "command_injection",
        "subcategory": "subprocess_shell",
        "cwe_id": "CWE-78",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""subprocess\.(call|run|Popen)\s*\(.*?shell\s*=\s*True""",
        "description": "subprocess with shell=True — command injection risk",
        "attack_vector": "shell=True passes string to shell interpreter, enabling injection.",
        "remediation": "Use subprocess.run(['cmd', 'arg1', 'arg2']) without shell=True.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "command_injection",
        "subcategory": "os_popen",
        "cwe_id": "CWE-78",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""os\.popen\s*\(""",
        "description": "os.popen() usage — potential command injection",
        "attack_vector": "os.popen() executes a shell command and returns a pipe to its output.",
        "remediation": "Use subprocess.run() with explicit argument lists.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-798: Hardcoded Credentials
    # OWASP A07:2021 — Identification and Authentication Failures
    # ──────────────────────────────────────────────────
    {
        "category": "hardcoded_secret",
        "subcategory": "api_key",
        "cwe_id": "CWE-798",
        "owasp_id": "A07:2021",
        "severity": "critical",
        "pattern": r"""(?i)(api[_-]?key|secret[_-]?key|password|token|auth[_-]?token)\s*[=:]\s*['"][A-Za-z0-9+/=!@#$%^&*]{8,}['"]""",
        "description": "Hardcoded secret or credential found in source code",
        "attack_vector": "Secrets in source code can be extracted from version control or build artifacts.",
        "remediation": "Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "hardcoded_secret",
        "subcategory": "aws_key",
        "cwe_id": "CWE-798",
        "owasp_id": "A07:2021",
        "severity": "critical",
        "pattern": r"""(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['"].+['"]""",
        "description": "Hardcoded AWS credential",
        "attack_vector": "AWS keys in code can be used to access cloud resources, incur charges, or steal data.",
        "remediation": "Use IAM roles, environment variables, or AWS credential files.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "hardcoded_secret",
        "subcategory": "db_password",
        "cwe_id": "CWE-798",
        "owasp_id": "A07:2021",
        "severity": "critical",
        "pattern": r"""(?i)(db[_-]?password|database[_-]?password|mysql[_-]?password|postgres[_-]?password)\s*[=:]\s*['"].+['"]""",
        "description": "Hardcoded database password",
        "attack_vector": "Database credentials in code allow unauthorized database access.",
        "remediation": "Use environment variables or a .env file (excluded from version control).",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "hardcoded_secret",
        "subcategory": "private_key",
        "cwe_id": "CWE-798",
        "owasp_id": "A07:2021",
        "severity": "critical",
        "pattern": r"""-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----""",
        "description": "Private key embedded in source code",
        "attack_vector": "Private keys in code compromise TLS, SSH, and signing operations.",
        "remediation": "Store private keys in secure key management systems, never in code.",
        "languages": "python,javascript,typescript,java",
        "source": "cwe_top25",
    },
    {
        "category": "hardcoded_secret",
        "subcategory": "jwt_secret",
        "cwe_id": "CWE-798",
        "owasp_id": "A07:2021",
        "severity": "high",
        "pattern": r"""(?i)(jwt[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*['"].{8,}['"]""",
        "description": "Hardcoded JWT or signing secret",
        "attack_vector": "Exposed JWT secrets allow token forgery and impersonation.",
        "remediation": "Rotate the secret and load from environment variables.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-22: Path Traversal
    # OWASP A01:2021 — Broken Access Control
    # ──────────────────────────────────────────────────
    {
        "category": "path_traversal",
        "subcategory": "dynamic_open",
        "cwe_id": "CWE-22",
        "owasp_id": "A01:2021",
        "severity": "high",
        "pattern": r"""open\s*\(.*?(\+|\.format|{).*?\)""",
        "description": "File open with dynamic path — potential path traversal",
        "attack_vector": "Attacker uses ../../../etc/passwd to access files outside intended directory.",
        "remediation": "Validate and sanitize file paths. Use os.path.realpath() and check against a base directory.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "path_traversal",
        "subcategory": "user_input_path",
        "cwe_id": "CWE-22",
        "owasp_id": "A01:2021",
        "severity": "high",
        "pattern": r"""Path\s*\(.*?(request|user_input|param|args|form)""",
        "description": "Path constructed from user input — path traversal risk",
        "attack_vector": "User-controlled path components enable directory traversal.",
        "remediation": "Use pathlib resolve() and verify the result is under the expected base directory.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "path_traversal",
        "subcategory": "send_file",
        "cwe_id": "CWE-22",
        "owasp_id": "A01:2021",
        "severity": "high",
        "pattern": r"""send_file\s*\(.*?(\+|\.format|{|request)""",
        "description": "Flask send_file() with dynamic path — path traversal risk",
        "attack_vector": "Unsanitized path in send_file allows downloading arbitrary server files.",
        "remediation": "Use send_from_directory() with a fixed base directory.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-502: Insecure Deserialization
    # OWASP A08:2021 — Software and Data Integrity Failures
    # ──────────────────────────────────────────────────
    {
        "category": "insecure_deserialization",
        "subcategory": "pickle",
        "cwe_id": "CWE-502",
        "owasp_id": "A08:2021",
        "severity": "high",
        "pattern": r"""pickle\.loads?\s*\(""",
        "description": "pickle.load(s) on potentially untrusted data — insecure deserialization",
        "attack_vector": "Attacker crafts a malicious pickle payload that executes arbitrary code on deserialization.",
        "remediation": "Use JSON or MessagePack for untrusted data. If pickle is needed, use hmac to verify integrity.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "insecure_deserialization",
        "subcategory": "yaml_unsafe",
        "cwe_id": "CWE-502",
        "owasp_id": "A08:2021",
        "severity": "high",
        "pattern": r"""yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)""",
        "description": "yaml.load() without SafeLoader — insecure deserialization",
        "attack_vector": "yaml.load() with default Loader can execute arbitrary Python objects.",
        "remediation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "insecure_deserialization",
        "subcategory": "shelve",
        "cwe_id": "CWE-502",
        "owasp_id": "A08:2021",
        "severity": "high",
        "pattern": r"""shelve\.open\s*\(""",
        "description": "shelve.open() uses pickle internally — deserialization risk",
        "attack_vector": "Shelve files from untrusted sources can execute code via pickle.",
        "remediation": "Avoid shelve for untrusted data. Use SQLite or JSON-based storage.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "insecure_deserialization",
        "subcategory": "marshal",
        "cwe_id": "CWE-502",
        "owasp_id": "A08:2021",
        "severity": "high",
        "pattern": r"""marshal\.loads?\s*\(""",
        "description": "marshal.load(s) — unsafe deserialization of untrusted data",
        "attack_vector": "marshal can crash the interpreter or execute code with crafted input.",
        "remediation": "Use JSON for data interchange. marshal is only safe for trusted .pyc files.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-95: Code Injection (eval/exec)
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "code_injection",
        "subcategory": "eval",
        "cwe_id": "CWE-95",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""eval\s*\(""",
        "description": "eval() usage — arbitrary code execution risk",
        "attack_vector": "eval() executes any Python expression, enabling full code injection.",
        "remediation": "Use ast.literal_eval() for safe evaluation of literals. Avoid eval() entirely.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "code_injection",
        "subcategory": "exec",
        "cwe_id": "CWE-95",
        "owasp_id": "A03:2021",
        "severity": "critical",
        "pattern": r"""exec\s*\(""",
        "description": "exec() usage — arbitrary code execution risk",
        "attack_vector": "exec() runs arbitrary Python statements, enabling full system compromise.",
        "remediation": "Avoid exec(). Use structured alternatives (dispatch tables, importlib).",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "code_injection",
        "subcategory": "compile",
        "cwe_id": "CWE-95",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""compile\s*\(.*?,\s*['"]exec['"]""",
        "description": "compile() in exec mode with potentially untrusted input",
        "attack_vector": "compile() + exec() chain allows execution of attacker-controlled code.",
        "remediation": "Avoid dynamic code compilation from untrusted sources.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-327: Weak Cryptography
    # OWASP A02:2021 — Cryptographic Failures
    # ──────────────────────────────────────────────────
    {
        "category": "weak_crypto",
        "subcategory": "md5",
        "cwe_id": "CWE-327",
        "owasp_id": "A02:2021",
        "severity": "medium",
        "pattern": r"""(?i)hashlib\.md5\s*\(""",
        "description": "MD5 hash usage — cryptographically broken",
        "attack_vector": "MD5 is vulnerable to collision attacks. Not suitable for passwords or integrity checks.",
        "remediation": "Use hashlib.sha256() or hashlib.blake2b(). For passwords, use bcrypt or argon2.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "weak_crypto",
        "subcategory": "sha1",
        "cwe_id": "CWE-327",
        "owasp_id": "A02:2021",
        "severity": "medium",
        "pattern": r"""(?i)hashlib\.sha1\s*\(""",
        "description": "SHA-1 hash usage — deprecated, collision attacks demonstrated",
        "attack_vector": "SHA-1 collisions have been produced (SHAttered attack). Not safe for security use.",
        "remediation": "Use SHA-256 or SHA-3 for integrity. For passwords, use bcrypt or argon2.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "weak_crypto",
        "subcategory": "des",
        "cwe_id": "CWE-327",
        "owasp_id": "A02:2021",
        "severity": "high",
        "pattern": r"""(?i)(DES\.new|Blowfish\.new|ARC4\.new|RC2\.new)""",
        "description": "Weak/deprecated cipher algorithm (DES, Blowfish, ARC4, RC2)",
        "attack_vector": "These ciphers have known weaknesses and can be brute-forced.",
        "remediation": "Use AES-256-GCM via cryptography.fernet or PyCryptodome AES.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "weak_crypto",
        "subcategory": "ecb_mode",
        "cwe_id": "CWE-327",
        "owasp_id": "A02:2021",
        "severity": "medium",
        "pattern": r"""(?i)MODE_ECB""",
        "description": "ECB cipher mode — deterministic encryption leaks patterns",
        "attack_vector": "ECB mode encrypts identical blocks to identical ciphertext, revealing data patterns.",
        "remediation": "Use CBC, GCM, or CTR mode with a random IV.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-918: Server-Side Request Forgery (SSRF)
    # OWASP A10:2021 — SSRF
    # ──────────────────────────────────────────────────
    {
        "category": "ssrf",
        "subcategory": "requests_dynamic",
        "cwe_id": "CWE-918",
        "owasp_id": "A10:2021",
        "severity": "high",
        "pattern": r"""requests\.(get|post|put|delete|head|patch)\s*\(.*?(\+|\.format|{|request\.)""",
        "description": "HTTP request with dynamic URL — potential SSRF",
        "attack_vector": "Attacker manipulates URL to access internal services (cloud metadata, admin panels).",
        "remediation": "Validate and allowlist destination URLs. Block private IP ranges.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "ssrf",
        "subcategory": "urllib_dynamic",
        "cwe_id": "CWE-918",
        "owasp_id": "A10:2021",
        "severity": "high",
        "pattern": r"""urllib\.request\.urlopen\s*\(.*?(\+|\.format|{|request\.)""",
        "description": "urllib.urlopen() with dynamic URL — SSRF risk",
        "attack_vector": "User-controlled URLs can target internal network resources.",
        "remediation": "Validate URLs against an allowlist before making requests.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-611: XML External Entity (XXE)
    # OWASP A05:2021 — Security Misconfiguration
    # ──────────────────────────────────────────────────
    {
        "category": "xxe",
        "subcategory": "etree_parse",
        "cwe_id": "CWE-611",
        "owasp_id": "A05:2021",
        "severity": "high",
        "pattern": r"""(?i)etree\.(parse|fromstring|XML)\s*\(""",
        "description": "XML parsing without disabling external entities — XXE risk",
        "attack_vector": "Malicious XML with external entities can read local files or trigger SSRF.",
        "remediation": "Use defusedxml library or disable external entity processing.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "xxe",
        "subcategory": "minidom",
        "cwe_id": "CWE-611",
        "owasp_id": "A05:2021",
        "severity": "high",
        "pattern": r"""minidom\.parse(String)?\s*\(""",
        "description": "xml.dom.minidom parsing — XXE vulnerability",
        "attack_vector": "minidom does not disable external entities by default.",
        "remediation": "Use defusedxml.minidom or lxml with resolve_entities=False.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-209: Information Exposure via Error Messages
    # OWASP A04:2021 — Insecure Design
    # ──────────────────────────────────────────────────
    {
        "category": "info_exposure",
        "subcategory": "debug_mode",
        "cwe_id": "CWE-209",
        "owasp_id": "A05:2021",
        "severity": "medium",
        "pattern": r"""(?i)(DEBUG\s*=\s*True|app\.debug\s*=\s*True|\.run\s*\(.*?debug\s*=\s*True)""",
        "description": "Debug mode enabled — exposes stack traces and internal state",
        "attack_vector": "Debug mode reveals file paths, config, and variable values to attackers.",
        "remediation": "Set DEBUG=False in production. Use environment variables for config.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "info_exposure",
        "subcategory": "traceback_print",
        "cwe_id": "CWE-209",
        "owasp_id": "A05:2021",
        "severity": "medium",
        "pattern": r"""traceback\.(print_exc|format_exc)\s*\(""",
        "description": "Traceback printed or formatted — may leak internal details",
        "attack_vector": "Stack traces reveal file paths, library versions, and internal logic.",
        "remediation": "Log tracebacks server-side only. Return generic error messages to users.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-1236: CSV Injection
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "csv_injection",
        "subcategory": "csv_write",
        "cwe_id": "CWE-1236",
        "owasp_id": "A03:2021",
        "severity": "medium",
        "pattern": r"""csv\.writer\s*\(.*?\)\.writerow\s*\(.*?(request|user_input|form)""",
        "description": "CSV output with user-controlled data — formula injection risk",
        "attack_vector": "Cells starting with =, +, -, @ can execute formulas when opened in Excel.",
        "remediation": "Prefix user data cells with a single quote or tab character.",
        "languages": "python",
        "source": "owasp_top10",
    },

    # ──────────────────────────────────────────────────
    # CWE-352: Cross-Site Request Forgery (CSRF)
    # OWASP A01:2021 — Broken Access Control
    # ──────────────────────────────────────────────────
    {
        "category": "csrf",
        "subcategory": "csrf_exempt",
        "cwe_id": "CWE-352",
        "owasp_id": "A01:2021",
        "severity": "medium",
        "pattern": r"""@csrf_exempt""",
        "description": "CSRF protection explicitly disabled on view",
        "attack_vector": "Without CSRF tokens, attackers can forge requests from victim's browser.",
        "remediation": "Remove @csrf_exempt and ensure CSRF middleware is enabled.",
        "languages": "python",
        "source": "owasp_top10",
    },

    # ──────────────────────────────────────────────────
    # CWE-295: Improper Certificate Validation
    # OWASP A07:2021 — Identification and Authentication Failures
    # ──────────────────────────────────────────────────
    {
        "category": "insecure_tls",
        "subcategory": "verify_false",
        "cwe_id": "CWE-295",
        "owasp_id": "A07:2021",
        "severity": "high",
        "pattern": r"""(?i)verify\s*=\s*False""",
        "description": "TLS certificate verification disabled — MITM risk",
        "attack_vector": "Disabling verify allows man-in-the-middle attacks on HTTPS connections.",
        "remediation": "Always use verify=True (default). Add custom CA certs if needed.",
        "languages": "python",
        "source": "cwe_top25",
    },
    {
        "category": "insecure_tls",
        "subcategory": "no_check_hostname",
        "cwe_id": "CWE-295",
        "owasp_id": "A07:2021",
        "severity": "high",
        "pattern": r"""check_hostname\s*=\s*False""",
        "description": "TLS hostname verification disabled — MITM risk",
        "attack_vector": "Without hostname checks, any valid cert is accepted, enabling MITM.",
        "remediation": "Keep check_hostname=True and use proper certificate validation.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-532: Logging Sensitive Data
    # OWASP A09:2021 — Security Logging and Monitoring Failures
    # ──────────────────────────────────────────────────
    {
        "category": "sensitive_logging",
        "subcategory": "log_password",
        "cwe_id": "CWE-532",
        "owasp_id": "A09:2021",
        "severity": "medium",
        "pattern": r"""(?i)(logging\.|logger\.|log\.)(info|debug|warning|error)\s*\(.*?(password|secret|token|api_key|credit_card)""",
        "description": "Sensitive data potentially written to logs",
        "attack_vector": "Credentials in logs can be harvested from log aggregation systems.",
        "remediation": "Mask or redact sensitive fields before logging.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-377: Insecure Temporary File
    # OWASP A04:2021 — Insecure Design
    # ──────────────────────────────────────────────────
    {
        "category": "insecure_temp",
        "subcategory": "mktemp",
        "cwe_id": "CWE-377",
        "owasp_id": "A04:2021",
        "severity": "medium",
        "pattern": r"""tempfile\.mktemp\s*\(""",
        "description": "tempfile.mktemp() — race condition vulnerability",
        "attack_vector": "mktemp returns a name but doesn't create the file, enabling symlink attacks.",
        "remediation": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-330: Weak Random
    # OWASP A02:2021 — Cryptographic Failures
    # ──────────────────────────────────────────────────
    {
        "category": "weak_random",
        "subcategory": "random_module",
        "cwe_id": "CWE-330",
        "owasp_id": "A02:2021",
        "severity": "medium",
        "pattern": r"""(?i)random\.(random|randint|choice|randrange|sample)\s*\(""",
        "description": "random module used for security-sensitive operation",
        "attack_vector": "Python's random module uses Mersenne Twister — predictable for crypto/tokens.",
        "remediation": "Use secrets.token_hex(), secrets.randbelow(), or os.urandom() for security.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-601: Open Redirect
    # OWASP A01:2021 — Broken Access Control
    # ──────────────────────────────────────────────────
    {
        "category": "open_redirect",
        "subcategory": "redirect_param",
        "cwe_id": "CWE-601",
        "owasp_id": "A01:2021",
        "severity": "medium",
        "pattern": r"""redirect\s*\(.*?(request\.|args\.|params\.|form\.)""",
        "description": "Redirect with user-controlled URL — open redirect risk",
        "attack_vector": "Attacker crafts a URL that redirects victims to malicious sites.",
        "remediation": "Validate redirect URLs against a whitelist of allowed domains.",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-943: NoSQL Injection
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "nosql_injection",
        "subcategory": "mongo_query",
        "cwe_id": "CWE-943",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""\.(find|find_one|update|delete|aggregate)\s*\(.*?(request\.|json\.loads|form\.)""",
        "description": "MongoDB query with unsanitized user input — NoSQL injection risk",
        "attack_vector": "Attacker passes {\"$gt\": \"\"} to bypass query filters.",
        "remediation": "Validate and type-check query parameters. Use a schema validation library.",
        "languages": "python",
        "source": "owasp_top10",
    },

    # ──────────────────────────────────────────────────
    # CWE-1333: ReDoS (Regular Expression Denial of Service)
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "redos",
        "subcategory": "nested_quantifier",
        "cwe_id": "CWE-1333",
        "owasp_id": "A03:2021",
        "severity": "medium",
        "pattern": r"""re\.(match|search|findall|sub)\s*\(.*?(\+\+|\*\+|\+\*|\*\*)""",
        "description": "Regex with nested quantifiers — potential ReDoS",
        "attack_vector": "Crafted input causes exponential backtracking, freezing the process.",
        "remediation": "Simplify regex. Use re2 or set a timeout with re.match(pattern, text, timeout=).",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-276: Incorrect Default Permissions
    # OWASP A01:2021 — Broken Access Control
    # ──────────────────────────────────────────────────
    {
        "category": "insecure_permissions",
        "subcategory": "world_writable",
        "cwe_id": "CWE-276",
        "owasp_id": "A01:2021",
        "severity": "medium",
        "pattern": r"""os\.chmod\s*\(.*?0o?777""",
        "description": "File permissions set to 777 — world-writable",
        "attack_vector": "Any user on the system can read, write, and execute the file.",
        "remediation": "Use restrictive permissions (0o600 for secrets, 0o755 for executables).",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-94: Improper Control of Code Generation
    # OWASP A03:2021 — Injection
    # ──────────────────────────────────────────────────
    {
        "category": "code_injection",
        "subcategory": "jinja_no_escape",
        "cwe_id": "CWE-94",
        "owasp_id": "A03:2021",
        "severity": "high",
        "pattern": r"""Environment\s*\(.*?autoescape\s*=\s*False""",
        "description": "Jinja2 Environment with autoescape disabled — injection risk",
        "attack_vector": "Templates render user input as raw HTML, enabling XSS.",
        "remediation": "Set autoescape=True or use select_autoescape().",
        "languages": "python",
        "source": "cwe_top25",
    },

    # ──────────────────────────────────────────────────
    # CWE-400: Resource Exhaustion / DoS
    # OWASP A04:2021 — Insecure Design
    # ──────────────────────────────────────────────────
    {
        "category": "resource_exhaustion",
        "subcategory": "unbounded_read",
        "cwe_id": "CWE-400",
        "owasp_id": "A04:2021",
        "severity": "medium",
        "pattern": r"""\.read\s*\(\s*\)""",
        "description": "Unbounded .read() — may consume all memory on large input",
        "attack_vector": "Attacker sends a massive payload causing OOM (Out of Memory) crash.",
        "remediation": "Use .read(max_size) or stream data in chunks.",
        "languages": "python",
        "source": "owasp_top10",
    },
]


def seed_vulnerability_patterns() -> int:
    """Seed the vulnerability_patterns table with CWE/OWASP patterns.

    Inserts all patterns if the table is empty. If patterns already exist,
    only inserts new ones (by checking cwe_id + subcategory uniqueness).

    Returns:
        Number of patterns inserted.
    """
    conn = get_connection()

    # Check existing count
    existing = conn.execute("SELECT COUNT(*) as cnt FROM vulnerability_patterns").fetchone()
    existing_count = existing["cnt"] if existing else 0

    if existing_count >= len(VULN_PATTERNS):
        conn.close()
        return 0

    # Get existing (cwe_id, subcategory) pairs to avoid duplicates
    existing_pairs: set[tuple[str, str]] = set()
    if existing_count > 0:
        rows = conn.execute("SELECT cwe_id, subcategory FROM vulnerability_patterns").fetchall()
        existing_pairs = {(row["cwe_id"], row["subcategory"] or "") for row in rows}

    inserted = 0
    for p in VULN_PATTERNS:
        pair = (p["cwe_id"], p.get("subcategory", ""))
        if pair in existing_pairs:
            continue

        conn.execute(
            """INSERT INTO vulnerability_patterns
               (category, subcategory, cwe_id, owasp_id, severity, pattern,
                description, attack_vector, remediation, languages, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                p["category"],
                p.get("subcategory"),
                p["cwe_id"],
                p.get("owasp_id"),
                p["severity"],
                p["pattern"],
                p["description"],
                p.get("attack_vector"),
                p.get("remediation"),
                p.get("languages", "python"),
                p.get("source", "cwe_top25"),
            ),
        )
        inserted += 1

    conn.commit()
    conn.close()
    return inserted


if __name__ == "__main__":
    init_db()
    count = seed_vulnerability_patterns()
    print(f"Seeded {count} vulnerability patterns into the database.")
    print(f"Total patterns available: {len(VULN_PATTERNS)}")
