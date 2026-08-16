"""Execution and orchestration engine for sanitized warehouse tasks.

Dispatches validated tasks to specific tool handlers, updates SQLite state,
and evaluates execution outcomes (retry vs escalation).
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agent.state import (
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_QUARANTINED,
    STATUS_RUNNING,
    StateStore,
)
from agent.tools import file_tool, http_tool, log_tool
from agent.validator import AnyTask, FileWriteTask, HttpFetchTask, LogEntryTask

_QUARANTINE_LOG = Path("logs") / "quarantine.jsonl"


@dataclass
class TaskExecutionResult:
    """Represents the outcome of an execution attempt."""

    task_id: str
    success: bool
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None
    escalated: bool = False


def execute_task(task: AnyTask, store: StateStore) -> TaskExecutionResult:
    """Dispatch a validated, sanitised task to the appropriate tool handler.

    Updates task state in SQLite and manages retry versus escalation logic.

    Args:
        task: A validated and sanitized task instance.
        store: SQLite state store for tracking lifecycle state.

    Returns:
        TaskExecutionResult describing what happened.
    """
    store.update_status(task.task_id, STATUS_RUNNING)

    try:
        if isinstance(task, HttpFetchTask):
            output = http_tool.run(
                url=task.params.url,
                output_key=task.params.output_key,
            )
        elif isinstance(task, FileWriteTask):
            output = file_tool.run(
                path=task.params.path,
                content=task.params.content,
            )
        elif isinstance(task, LogEntryTask):
            output = log_tool.run(
                message=task.params.message,
                level=task.params.level,
            )
        else:
            raise ValueError(f"Unknown task type: {type(task)}")

        # Success path: mark done and save output
        store.update_status(task.task_id, STATUS_DONE, result=output)
        return TaskExecutionResult(
            task_id=task.task_id,
            success=True,
            status=STATUS_DONE,
            result=output,
        )

    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {str(exc)}"
        current_attempts = store.increment_attempts(task.task_id)

        # Decision logic: Retry vs Escalate
        escalated = current_attempts >= task.retry_limit
        store.update_status(
            task_id=task.task_id,
            status=STATUS_FAILED,
            error=error_msg,
        )

        return TaskExecutionResult(
            task_id=task.task_id,
            success=False,
            status=STATUS_FAILED,
            error=error_msg,
            escalated=escalated,
        )


def quarantine_task(
    task_id: str,
    raw_task: dict,
    violations: list[str],
    store: StateStore,
) -> None:
    """Quarantine an untrusted task that failed validation or sanitisation.

    Updates SQLite status to 'quarantined' so it is permanently ignored in
    future cycles, and writes an audit record to logs/quarantine.jsonl.

    Args:
        task_id: The identifier of the flagged task.
        raw_task: The raw dictionary definition of the task.
        violations: List of security/schema violations detected.
        store: SQLite state store to update.
    """
    store.record_seen(task_id)
    error_summary = "; ".join(violations)
    store.update_status(
        task_id=task_id,
        status=STATUS_QUARANTINED,
        error=error_summary,
    )

    _QUARANTINE_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "task_id": task_id,
        "violations": violations,
        "raw_task": raw_task,
    }

    with _QUARANTINE_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")
