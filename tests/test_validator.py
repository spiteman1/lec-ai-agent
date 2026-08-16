"""Unit tests for Pydantic schema validation and structural security rules."""

import pytest
from pydantic import TypeAdapter, ValidationError

from agent.validator import (
    AnyTask,
    FileWriteTask,
    HttpFetchTask,
    LogEntryTask,
    validate_feed,
)

task_adapter = TypeAdapter(AnyTask)


def test_valid_http_fetch_task() -> None:
    """Test that a well-formed http_fetch task parses cleanly."""
    raw = {
        "task_id": "task-001",
        "type": "http_fetch",
        "description": "Fetch weather status report",
        "priority": 1,
        "retry_limit": 3,
        "params": {
            "url": "https://wttr.in/London?format=3",
            "output_key": "weather_data",
        },
    }
    task = task_adapter.validate_python(raw)
    assert isinstance(task, HttpFetchTask)
    assert task.task_id == "task-001"
    assert task.params.url == "https://wttr.in/London?format=3"
    assert task.params.output_key == "weather_data"


def test_valid_file_write_task() -> None:
    """Test that a well-formed file_write task parses cleanly."""
    raw = {
        "task_id": "task-002",
        "type": "file_write",
        "description": "Save report to disk",
        "priority": 2,
        "retry_limit": 1,
        "params": {
            "path": "reports/daily.txt",
            "content": "All systems nominal.",
        },
    }
    task = task_adapter.validate_python(raw)
    assert isinstance(task, FileWriteTask)
    assert task.params.path == "reports/daily.txt"
    assert task.params.content == "All systems nominal."


def test_valid_log_entry_task() -> None:
    """Test that a well-formed log_entry task parses cleanly."""
    raw = {
        "task_id": "task-003",
        "type": "log_entry",
        "description": "Log sync completion event",
        "priority": 1,
        "retry_limit": 0,
        "params": {
            "message": "Sync completed successfully.",
            "level": "INFO",
        },
    }
    task = task_adapter.validate_python(raw)
    assert isinstance(task, LogEntryTask)
    assert task.params.level == "INFO"


def test_missing_required_params_rejected() -> None:
    """Test that a file_write task missing 'path' fails validation (Scenario 2)."""
    raw = {
        "task_id": "task-002",
        "type": "file_write",
        "description": "Write a status report to disk.",
        "priority": 2,
        "retry_limit": 1,
        "params": {
            # 'path' is intentionally missing
            "content": "System status: all checks passed.",
        },
    }
    with pytest.raises(ValidationError) as exc_info:
        task_adapter.validate_python(raw)

    errors = exc_info.value.errors()
    assert any("path" in str(err["loc"]) for err in errors)


def test_extra_fields_forbidden() -> None:
    """Test that extra undeclared fields trigger ValidationError due to extra='forbid'."""
    raw = {
        "task_id": "task-001",
        "type": "http_fetch",
        "description": "Fetch weather",
        "priority": 1,
        "retry_limit": 3,
        "injected_field": "dangerous_payload",  # Forbidden extra field
        "params": {
            "url": "https://wttr.in/London?format=3",
            "output_key": "weather",
        },
    }
    with pytest.raises(ValidationError) as exc_info:
        task_adapter.validate_python(raw)

    errors = exc_info.value.errors()
    assert any("extra_forbidden" in err["type"] for err in errors)


def test_invalid_task_id_format_rejected() -> None:
    """Test that task_id values with uppercase, spaces, or traversal slashes fail."""
    invalid_ids = [
        "TASK-001",           # Uppercase rejected
        "task_001",           # Underscore rejected (must be hyphen)
        "task-001/../bad",    # Slash/traversal rejected
        "task 001",           # Space rejected
        "invalid-prefix-01",  # Missing 'task-' prefix
    ]
    for bad_id in invalid_ids:
        raw = {
            "task_id": bad_id,
            "type": "log_entry",
            "description": "Testing ID validator",
            "priority": 1,
            "retry_limit": 1,
            "params": {"message": "test", "level": "INFO"},
        }
        with pytest.raises(ValidationError):
            task_adapter.validate_python(raw)


def test_unknown_task_type_rejected() -> None:
    """Test that unsupported or hostile task types fail union discrimination."""
    raw = {
        "task_id": "task-999",
        "type": "shell_exec",  # Unsupported task type
        "description": "Execute arbitrary shell script",
        "priority": 1,
        "retry_limit": 0,
        "params": {"command": "whoami"},
    }
    with pytest.raises(ValidationError):
        task_adapter.validate_python(raw)


def test_numeric_bounds_validation() -> None:
    """Test that priority must be >= 1 and retry_limit must be between 0 and 5."""
    # Priority < 1 should fail
    with pytest.raises(ValidationError):
        task_adapter.validate_python({
            "task_id": "task-001",
            "type": "log_entry",
            "description": "Test priority bounds",
            "priority": 0,
            "retry_limit": 1,
            "params": {"message": "test", "level": "INFO"},
        })

    # Retry limit > 5 should fail (resource exhaustion defense)
    with pytest.raises(ValidationError):
        task_adapter.validate_python({
            "task_id": "task-001",
            "type": "log_entry",
            "description": "Test retry limit bounds",
            "priority": 1,
            "retry_limit": 50,
            "params": {"message": "test", "level": "INFO"},
        })


def test_validate_feed_envelope() -> None:
    """Test validating an entire feed structure."""
    feed_data = {
        "feed_version": "1.0",
        "tasks": [
            {
                "task_id": "task-001",
                "type": "log_entry",
                "description": "Test feed validation",
                "priority": 1,
                "retry_limit": 0,
                "params": {"message": "ok", "level": "INFO"},
            }
        ],
    }
    feed = validate_feed(feed_data)
    assert feed.feed_version == "1.0"
    assert len(feed.tasks) == 1
