
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_NAME = str(BASE_DIR / "sentinel_audit.db")


def initialize_database():
    connection = sqlite3.connect(DATABASE_NAME)

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                reason TEXT
            )
            """
        )
        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def log_event(event_type, status_code, reason=""):
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Event type must be a non-empty string.")

    if isinstance(status_code, bool) or not isinstance(status_code, int):
        raise ValueError("Status code must be an integer.")

    if not 100 <= status_code <= 599:
        raise ValueError("Status code must be between 100 and 599.")

    if not isinstance(reason, str):
        raise ValueError("Reason must be a string.")

    connection = sqlite3.connect(DATABASE_NAME)

    try:
        connection.execute(
            """
            INSERT INTO audit_logs (
                timestamp,
                event_type,
                status_code,
                reason
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                event_type.strip(),
                status_code,
                reason,
            ),
        )
        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()
