"""SQLite persistence and audit logging layer for Automotive Code Review.

Supports:
- Projects & Review Sessions
- Findings with Developer & Reviewer Dispositions (Accept, Reject, False Positive, Mitigated)
- Formal Engineering Reviewer Sign-Off
- ISO 26262 / ISO 21434 Traceable Audit Logs
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "reviews_audit.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize SQLite tables for reviews, findings, and audit logs."""
    conn = get_connection()
    try:
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    language TEXT NOT NULL,
                    files_analyzed TEXT NOT NULL,
                    ai_provider TEXT NOT NULL,
                    ai_model TEXT NOT NULL,
                    review_status TEXT NOT NULL DEFAULT 'Pending Review',
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    summary_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    review_id INTEGER NOT NULL,
                    finding_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    file TEXT NOT NULL,
                    function TEXT,
                    line TEXT,
                    code_evidence TEXT,
                    description TEXT,
                    root_cause TEXT,
                    relevant_rule TEXT,
                    suggested_fix TEXT,
                    confidence TEXT,
                    source TEXT,
                    disposition TEXT NOT NULL DEFAULT 'Pending Review',
                    reviewer_notes TEXT DEFAULT '',
                    FOREIGN KEY (review_id) REFERENCES reviews (id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user TEXT NOT NULL,
                    action TEXT NOT NULL,
                    review_id INTEGER,
                    details_json TEXT
                );
                """
            )
    finally:
        conn.close()


def save_review(
    language: str,
    files: list[str],
    ai_provider: str,
    ai_model: str,
    summary: dict,
    findings: list[dict],
    user: str = "engineer",
) -> int:
    """Save a new review session and its findings to the database."""
    init_db()
    conn = get_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO reviews (created_at, language, files_analyzed, ai_provider, ai_model, review_status, summary_json)
                VALUES (?, ?, ?, ?, ?, 'Pending Review', ?)
                """,
                (now_iso, language, json.dumps(files), ai_provider, ai_model, json.dumps(summary)),
            )
            review_id = cur.lastrowid

            for f in findings:
                cur.execute(
                    """
                    INSERT INTO findings (
                        review_id, finding_id, category, severity, title, file,
                        function, line, code_evidence, description, root_cause,
                        relevant_rule, suggested_fix, confidence, source, disposition, reviewer_notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        review_id,
                        f.get("finding_id", ""),
                        f.get("category", "Quality"),
                        f.get("severity", "Low"),
                        f.get("title", ""),
                        f.get("file", ""),
                        f.get("function", "unknown"),
                        str(f.get("line", "unknown")),
                        f.get("code_evidence", ""),
                        f.get("description", ""),
                        f.get("root_cause", ""),
                        f.get("relevant_rule", ""),
                        f.get("suggested_fix", ""),
                        f.get("confidence", "Medium"),
                        f.get("source", "Local Review"),
                        f.get("disposition", "Pending Review"),
                        f.get("reviewer_notes", ""),
                    ),
                )

            # Record audit log
            cur.execute(
                """
                INSERT INTO audit_logs (timestamp, user, action, review_id, details_json)
                VALUES (?, ?, 'CREATE_REVIEW', ?, ?)
                """,
                (
                    now_iso,
                    user,
                    review_id,
                    json.dumps({"files": files, "language": language, "finding_count": len(findings)}),
                ),
            )
            return review_id
    finally:
        conn.close()


def update_finding_disposition(
    review_id: int,
    finding_id: str,
    disposition: str,
    reviewer_notes: str,
    user: str = "reviewer",
) -> None:
    """Update developer/reviewer disposition and log the audit change."""
    conn = get_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute(
                """
                UPDATE findings
                SET disposition = ?, reviewer_notes = ?
                WHERE review_id = ? AND finding_id = ?
                """,
                (disposition, reviewer_notes, review_id, finding_id),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp, user, action, review_id, details_json)
                VALUES (?, ?, 'UPDATE_DISPOSITION', ?, ?)
                """,
                (
                    now_iso,
                    user,
                    review_id,
                    json.dumps({"finding_id": finding_id, "disposition": disposition, "notes": reviewer_notes}),
                ),
            )
    finally:
        conn.close()


def sign_off_review(
    review_id: int,
    reviewer_name: str,
    status: str = "Approved with Dispositions",
) -> None:
    """Record formal engineering sign-off for governance and compliance."""
    conn = get_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute(
                """
                UPDATE reviews
                SET review_status = ?, reviewed_by = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (status, reviewer_name, now_iso, review_id),
            )
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp, user, action, review_id, details_json)
                VALUES (?, ?, 'FORMAL_SIGN_OFF', ?, ?)
                """,
                (
                    now_iso,
                    reviewer_name,
                    review_id,
                    json.dumps({"status": status, "signed_at": now_iso}),
                ),
            )
    finally:
        conn.close()


def get_recent_reviews(limit: int = 10) -> list[dict]:
    """Retrieve recent review sessions."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, created_at, language, files_analyzed, ai_provider, ai_model, review_status, reviewed_by, reviewed_at
            FROM reviews
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_audit_trail(review_id: int | None = None, limit: int = 50) -> list[dict]:
    """Retrieve audit history for traceability."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.cursor()
        if review_id:
            cur.execute(
                """
                SELECT id, timestamp, user, action, review_id, details_json
                FROM audit_logs
                WHERE review_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (review_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, timestamp, user, action, review_id, details_json
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
