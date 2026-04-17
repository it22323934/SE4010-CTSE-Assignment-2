-- CodeSentinel Database Schema
-- Tracks audit runs, findings, file metrics, and refactoring actions across runs.

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
    status          TEXT DEFAULT 'running',
    summary_json    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL,
    finding_uid     TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_start      INTEGER,
    line_end        INTEGER,
    category        TEXT NOT NULL,
    agent_source    TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cwe_id          TEXT,
    description     TEXT NOT NULL,
    suggestion      TEXT,
    confidence      REAL DEFAULT 0.5,
    status          TEXT DEFAULT 'open',
    first_seen_run  INTEGER,
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
    change_frequency INTEGER DEFAULT 0,
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
    depends_on      TEXT,
    status          TEXT DEFAULT 'pending',
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
