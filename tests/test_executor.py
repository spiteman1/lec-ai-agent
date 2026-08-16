"""Unit tests for task execution, sandbox enforcement, and retry/escalate logic."""

from pathlib import Path

import pytest

from agent.executor import execute_task, quarantine_task
from agent.state import (
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_QUARANTINED,
    StateStore,
)
from agent.tools import file_tool
from agent.validator import (
    FileWriteParams,
    FileWriteTask,
    LogEntryParams,
    LogEntryTask,
)


def test_execute_log_entry_success(tmp_path: Path) -> None:
    """Test executing a clean log_entry task updates state to done."""
    db_path = str(tmp_path / "test_state.db")
    with StateStore(db_path) as store:
        task = LogEntryTask(
            task_id="task-001",
            type="log_entry",
            description="Testing log tool",
            priority=1,
            retry_limit=1,
            params=LogEntryParams(message="Unit test log message", level="INFO"),
        )
        store.record_seen(task.task_id)
        result = execute_task(task, store)

        assert result.success
        assert result.status == STATUS_DONE

        record = store.get_task(task.task_id)
        assert record is not None
        assert record.status == STATUS_DONE
        assert record.result is not None


def test_file_write_sandbox_escape_blocked() -> None:
    """Test that file_tool blocks paths escaping the sandbox directory."""
    with pytest.raises(PermissionError) as exc_info:
        # Attempt to escape output sandbox using parent relative segments
        file_tool.run(path="../../escaped.txt", content="evil payload")

    assert "sandbox" in str(exc_info.value).lower()


def test_retry_and_escalate_logic(tmp_path: Path) -> None:
    """Test that failure increments attempts and escalates when retry_limit is hit."""
    db_path = str(tmp_path / "test_state.db")
    with StateStore(db_path) as store:
        # Create a task with retry_limit = 2 that will fail (unwritable path)
        task = FileWriteTask(
            task_id="task-fail",
            type="file_write",
            description="Task doomed to fail",
            priority=1,
            retry_limit=2,
            params=FileWriteParams(
                path="../../blocked.txt",  # will raise PermissionError
                content="data",
            ),
        )
        store.record_seen(task.task_id)

        # Attempt 1: Should fail, but NOT escalate yet (1 < 2)
        res1 = execute_task(task, store)
        assert not res1.success
        assert res1.status == STATUS_FAILED
        assert not res1.escalated
        rec1 = store.get_task(task.task_id)
        assert rec1 is not None
        assert rec1.attempts == 1

        # Attempt 2: Should fail AND trigger escalation (2 >= 2)
        res2 = execute_task(task, store)
        assert not res2.success
        assert res2.status == STATUS_FAILED
        assert res2.escalated
        rec2 = store.get_task(task.task_id)
        assert rec2 is not None
        assert rec2.attempts == 2


def test_quarantine_records_and_audit(tmp_path: Path) -> None:
    """Test that quarantine_task updates SQLite state and writes audit log."""
    db_path = str(tmp_path / "test_state.db")
    with StateStore(db_path) as store:
        task_id = "task-malicious"
        raw_payload = {"task_id": task_id, "bad": True}
        violations = ["Code injection: os.system detected"]

        quarantine_task(task_id, raw_payload, violations, store)

        record = store.get_task(task_id)
        assert record is not None
        assert record.status == STATUS_QUARANTINED
        assert "Code injection" in str(record.error)
