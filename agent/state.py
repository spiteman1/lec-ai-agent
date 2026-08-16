"""Persistent state store for the agent, backed by SQLite.

WHY SQLITE:
    This agent is a single process running on one machine. Nothing else
    needs to read or write its state concurrently. SQLite is a single file,
    needs no server, and is part of Python's standard library. It is the
    correct tool for this scope. In production, where multiple agent replicas
    might run in parallel, we'd swap to Postgres 
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Status constants
# Using plain strings rather than an Enum keeps the SQLite queries readable
# and avoids having to serialise/deserialise enum values.
# ---------------------------------------------------------------------------

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_QUARANTINED = "quarantined"


# ---------------------------------------------------------------------------
# Data class for a task record read back from the DB
# ---------------------------------------------------------------------------

@dataclass
class TaskRecord:
    """A row from the tasks table."""

    task_id: str
    status: str
    attempts: int
    last_seen: str       # ISO 8601 UTC timestamp string
    result: Optional[dict]   # Execution result, if any (stored as JSON)
    error: Optional[str]     # Error message, if task failed or was quarantined


# ---------------------------------------------------------------------------
# StateStore
# ---------------------------------------------------------------------------

class StateStore:
    """Manages task state across agent poll cycles using a SQLite database.

    Usage:
        store = StateStore("agent_state.db")
        store.record_seen("task-001")
        store.update_status("task-001", STATUS_DONE, result={"output": "..."})
        store.close()

    Or use it as a context manager:
        with StateStore("agent_state.db") as store:
            ...
    """

    def __init__(self, db_path: str = "agent_state.db") -> None:
        """Open (or create) the SQLite database and initialise the schema."""
        self._path = Path(db_path)
        # check_same_thread=False is safe here because we only ever access
        # the store from a single thread (the poll loop). If this were
        # multi-threaded we'd use connection pooling instead.
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row  # lets us access columns by name
        self._initialise_schema()

    def _initialise_schema(self) -> None:
        """Create the tasks table if it does not already exist.
        """
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id     TEXT    PRIMARY KEY,
                status      TEXT    NOT NULL,
                attempts    INTEGER NOT NULL DEFAULT 0,
                last_seen   TEXT    NOT NULL,
                result      TEXT,
                error       TEXT
            )
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def record_seen(self, task_id: str) -> None:
        """Record that a task has been seen for the first time.

        Uses INSERT OR IGNORE so that if we see the same task_id on a
        subsequent poll cycle, this is a no-op -- we don't overwrite
        existing state (like a 'done' status) just because we saw it again.
        """
        self._conn.execute(
            """
            INSERT OR IGNORE INTO tasks (task_id, status, attempts, last_seen)
            VALUES (?, ?, 0, ?)
            """,
            (task_id, STATUS_PENDING, _now()),
        )
        self._conn.commit()

    def update_status(
        self,
        task_id: str,
        status: str,
        result: Optional[dict] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update the status (and optionally result/error) of a task."""
        self._conn.execute(
            """
            UPDATE tasks
            SET status = ?, result = ?, error = ?, last_seen = ?
            WHERE task_id = ?
            """,
            (
                status,
                json.dumps(result) if result is not None else None,
                error,
                _now(),
                task_id,
            ),
        )
        self._conn.commit()

    def increment_attempts(self, task_id: str) -> int:
        """Increment the attempt counter and return the new value."""
        self._conn.execute(
            "UPDATE tasks SET attempts = attempts + 1, last_seen = ? WHERE task_id = ?",
            (_now(), task_id),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT attempts FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        return row["attempts"] if row else 0

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def has_been_seen(self, task_id: str) -> bool:
        """Return True if this task_id has been recorded before."""
        row = self._conn.execute(
            "SELECT 1 FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        return row is not None

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        """Fetch a single task record by ID. Returns None if not found."""
        row = self._conn.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            return None
        return _row_to_record(row)

    def get_all_tasks(self) -> list[TaskRecord]:
        """Fetch all task records, ordered by last_seen descending."""
        rows = self._conn.execute(
            "SELECT * FROM tasks ORDER BY last_seen DESC"
        ).fetchall()
        return [_row_to_record(r) for r in rows]

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _row_to_record(row: sqlite3.Row) -> TaskRecord:
    """Convert a sqlite3.Row to a TaskRecord dataclass."""
    return TaskRecord(
        task_id=row["task_id"],
        status=row["status"],
        attempts=row["attempts"],
        last_seen=row["last_seen"],
        result=json.loads(row["result"]) if row["result"] else None,
        error=row["error"],
    )
