CREATE TABLE IF NOT EXISTS tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    parameter TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,
    tool_used TEXT NOT NULL DEFAULT '[]',
    tested INTEGER DEFAULT 0,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (target, endpoint, parameter, vulnerability_class)
);

CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,
    parameter TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,
    tool_used TEXT NOT NULL DEFAULT '[]',
    tested_status TEXT NOT NULL DEFAULT 'untested',
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (endpoint, parameter, vulnerability_class)
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    subdomains TEXT,
    open_ports TEXT,
    js_hashes TEXT
);
