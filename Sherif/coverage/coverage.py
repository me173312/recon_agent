"""SQLite-backed coverage tracker for tested recon endpoints.

The public API remains compatible with the original module while adding
tool-aware deduplication. The canonical uniqueness key is now:
``(endpoint, parameter, vulnerability_class)``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, List, Sequence


MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(MODULE_DIR, "coverage.db")
SCHEMA_PATH = os.path.join(MODULE_DIR, "schema.sql")


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection configured for dictionary-like rows."""

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Create or migrate the coverage database."""

    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"Schema file not found at {SCHEMA_PATH}")

    with open(SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
        schema_script = schema_file.read()

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.executescript(schema_script)
            _ensure_column(cursor, "tracking", "tool_used", "TEXT NOT NULL DEFAULT '[]'")
            _ensure_tracking_tool_index(cursor)
            _backfill_coverage_from_tracking(cursor)
            conn.commit()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Database initialization failed: {exc}") from exc


def mark_tested(
    target: str,
    endpoint: str,
    parameter: str,
    vulnerability_class: str,
    tool_used: str | Sequence[str] | None = None,
) -> None:
    """Mark a vulnerability class as tested and append reporting tools.

    If the same ``endpoint``, ``parameter``, and ``vulnerability_class`` already
    exist, only ``tool_used`` and tested status are updated. Existing tool names
    are preserved and never duplicated.
    """

    tools = _normalize_tool_names(tool_used)

    try:
        initialize_database()
        with get_connection() as conn:
            cursor = conn.cursor()

            coverage_row = _fetch_coverage_row(cursor, endpoint, parameter, vulnerability_class)
            if coverage_row:
                merged_tools = _merge_tool_used(coverage_row["tool_used"], tools)
                cursor.execute(
                    """
                    UPDATE coverage
                    SET tool_used = ?, tested_status = ?, tested_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (json.dumps(merged_tools), "tested", coverage_row["id"]),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO coverage (
                        endpoint, parameter, vulnerability_class, tool_used, tested_status
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (endpoint, parameter, vulnerability_class, json.dumps(tools), "tested"),
                )

            tracking_row = _fetch_tracking_row(cursor, endpoint, parameter, vulnerability_class)
            if tracking_row:
                merged_tools = _merge_tool_used(tracking_row["tool_used"], tools)
                cursor.execute(
                    """
                    UPDATE tracking
                    SET tool_used = ?, tested = 1, tested_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (json.dumps(merged_tools), tracking_row["id"]),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO tracking (
                        target, endpoint, parameter, vulnerability_class, tool_used, tested
                    )
                    VALUES (?, ?, ?, ?, ?, 1)
                    """,
                    (target, endpoint, parameter, vulnerability_class, json.dumps(tools)),
                )

            conn.commit()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to mark as tested: {exc}") from exc


def get_untested(target: str) -> List[Dict[str, Any]]:
    """Return untested rows for a target from the compatibility tracking table."""

    try:
        initialize_database()
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    id, target, endpoint, parameter, vulnerability_class,
                    tool_used, tested, tested_at
                FROM tracking
                WHERE target = ? AND tested = 0
                """,
                (target,),
            )

            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to get untested entries: {exc}") from exc


def add_scan_snapshot(
    target: str,
    subdomains: List[str],
    open_ports: List[int],
    js_hashes: Dict[str, str],
) -> None:
    """Persist a scan-history snapshot for later comparison."""

    try:
        initialize_database()
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (target, subdomains, open_ports, js_hashes)
                VALUES (?, ?, ?, ?)
                """,
                (
                    target,
                    json.dumps(subdomains),
                    json.dumps(open_ports),
                    json.dumps(js_hashes),
                ),
            )
            conn.commit()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Failed to add scan snapshot: {exc}") from exc


def _fetch_coverage_row(
    cursor: sqlite3.Cursor,
    endpoint: str,
    parameter: str,
    vulnerability_class: str,
) -> sqlite3.Row | None:
    cursor.execute(
        """
        SELECT id, tool_used
        FROM coverage
        WHERE endpoint = ? AND parameter = ? AND vulnerability_class = ?
        """,
        (endpoint, parameter, vulnerability_class),
    )
    return cursor.fetchone()


def _fetch_tracking_row(
    cursor: sqlite3.Cursor,
    endpoint: str,
    parameter: str,
    vulnerability_class: str,
) -> sqlite3.Row | None:
    cursor.execute(
        """
        SELECT id, tool_used
        FROM tracking
        WHERE endpoint = ? AND parameter = ? AND vulnerability_class = ?
        ORDER BY tested_at DESC, id DESC
        LIMIT 1
        """,
        (endpoint, parameter, vulnerability_class),
    )
    return cursor.fetchone()


def _ensure_column(cursor: sqlite3.Cursor, table_name: str, column_name: str, definition: str) -> None:
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing_columns = {row["name"] for row in cursor.fetchall()}
    if column_name not in existing_columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def _ensure_tracking_tool_index(cursor: sqlite3.Cursor) -> None:
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_tracking_endpoint_parameter_vuln
        ON tracking (endpoint, parameter, vulnerability_class)
        """
    )


def _backfill_coverage_from_tracking(cursor: sqlite3.Cursor) -> None:
    cursor.execute(
        """
        INSERT OR IGNORE INTO coverage (
            endpoint, parameter, vulnerability_class, tool_used, tested_status, tested_at
        )
        SELECT
            endpoint,
            parameter,
            vulnerability_class,
            COALESCE(tool_used, '[]'),
            CASE WHEN tested = 1 THEN 'tested' ELSE 'untested' END,
            tested_at
        FROM tracking
        """
    )


def _normalize_tool_names(tool_used: str | Sequence[str] | None) -> List[str]:
    if tool_used is None:
        return []
    if isinstance(tool_used, str):
        candidates = [tool_used]
    else:
        candidates = [str(tool) for tool in tool_used]

    normalized: List[str] = []
    seen: set[str] = set()
    for tool in candidates:
        name = tool.strip()
        if name and name not in seen:
            seen.add(name)
            normalized.append(name)
    return normalized


def _merge_tool_used(existing_json: str | None, new_tools: Sequence[str]) -> List[str]:
    merged: List[str] = []
    seen: set[str] = set()

    for tool in _load_tool_used(existing_json):
        if tool not in seen:
            seen.add(tool)
            merged.append(tool)

    for tool in new_tools:
        if tool not in seen:
            seen.add(tool)
            merged.append(tool)

    return merged


def _load_tool_used(existing_json: str | None) -> List[str]:
    if not existing_json:
        return []

    try:
        decoded = json.loads(existing_json)
    except json.JSONDecodeError:
        return [existing_json]

    if isinstance(decoded, list):
        return [str(tool) for tool in decoded if str(tool).strip()]
    if isinstance(decoded, str) and decoded.strip():
        return [decoded.strip()]
    return []


if not os.path.exists(DB_PATH):
    initialize_database()
