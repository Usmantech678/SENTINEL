
import sqlite3
from unittest.mock import patch

import pytest

import audit


def test_log_event_saves_record():
    audit.log_event(
        "TEST_EVENT",
        200,
        "Audit test",
    )

    connection = sqlite3.connect(audit.DATABASE_NAME)

    try:
        result = connection.execute(
            """
            SELECT event_type, status_code, reason
            FROM audit_logs
            WHERE event_type = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("TEST_EVENT",),
        ).fetchone()
    finally:
        connection.close()

    assert result == ("TEST_EVENT", 200, "Audit test")


def test_log_event_rejects_empty_event_type():
    with pytest.raises(ValueError):
        audit.log_event("", 200, "Test")


def test_log_event_rejects_invalid_status_code():
    with pytest.raises(ValueError):
        audit.log_event("TEST_EVENT", 99, "Test")


def test_log_event_rejects_boolean_status_code():
    with pytest.raises(ValueError):
        audit.log_event("TEST_EVENT", True, "Test")


def test_log_event_rejects_non_string_reason():
    with pytest.raises(ValueError):
        audit.log_event("TEST_EVENT", 200, None)


def test_log_event_closes_connection_after_database_error():
    with patch(
        "audit.sqlite3.connect",
    ) as mock_connect:
        mock_connection = mock_connect.return_value
        mock_connection.execute.side_effect = sqlite3.OperationalError(
            "Simulated database failure"
        )

        with pytest.raises(sqlite3.OperationalError):
            audit.log_event("TEST_EVENT", 200, "Test")

        mock_connection.rollback.assert_called_once()
        mock_connection.close.assert_called_once()
