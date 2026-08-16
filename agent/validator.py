"""Schema validation for warehouse feed tasks using Pydantic."""

# Why Pydantic v2?
# Pydantic lets us declare exactly what a valid task looks like as a Python
# class. If incoming data doesn't match, it raises a ValidationError with
# a clear message -- no silent corruption of bad data.
#
# We use a "discriminated union" pattern: the `type` field tells Pydantic
# which params shape to expect. This is how task-002 gets caught -- it
# claims to be a file_write but its params are missing the required `path`
# field. Pydantic rejects it before we ever touch the content.

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Params models -- one per task type
# Each defines the exact fields that type of task is allowed to have.
# `extra='forbid'` means any field not listed here causes a ValidationError.
# ---------------------------------------------------------------------------

class HttpFetchParams(BaseModel):
    """Params for an http_fetch task."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="The URL to fetch.")
    output_key: str = Field(..., description="Key to store the result under.")


class FileWriteParams(BaseModel):
    """Params for a file_write task."""

    model_config = ConfigDict(extra="forbid")

    # `path` is required -- this is exactly what task-002 is missing.
    path: str = Field(..., description="Relative output path for the file.")
    content: str = Field(..., description="Content to write to the file.")


class LogEntryParams(BaseModel):
    """Params for a log_entry task."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., description="The message to log.")
    # `level` is a Literal -- only these exact strings are accepted.
    # "CRITICAL" isn't in the list? Rejected. Simple, powerful.
    level: Literal["INFO", "WARNING", "ERROR"] = Field(..., description="Log level.")


# ---------------------------------------------------------------------------
# Per-type task models
# Each wraps its matching Params model and locks the `type` field to a
# specific Literal value. Pydantic uses that Literal to route the union.
# ---------------------------------------------------------------------------

class _BaseTask(BaseModel):
    """Shared fields every task must have, regardless of type."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="Unique task identifier.")
    description: str = Field(..., description="Human-readable task description.")
    priority: int = Field(..., ge=1, description="Execution priority (1 = highest).")
    retry_limit: int = Field(..., ge=0, le=5, description="Max retry attempts on failure.")

    @field_validator("task_id")
    @classmethod
    def task_id_must_be_slug(cls, value: str) -> str:
        """Enforce task_id format: 'task-' followed by lowercase alphanumerics/hyphens.

        Why: an allowlist pattern. We define exactly what a valid ID looks like.
        Anything that doesn't match -- including IDs crafted to escape logging
        systems (e.g. newline injection, unicode tricks) -- is rejected here.
        """
        import re
        if not re.fullmatch(r"task-[a-z0-9][a-z0-9-]{0,48}", value):
            raise ValueError(
                f"task_id '{value}' must match pattern 'task-[a-z0-9-]+' (max 50 chars)."
            )
        return value


class HttpFetchTask(_BaseTask):
    """A validated http_fetch task."""

    type: Literal["http_fetch"]
    params: HttpFetchParams


class FileWriteTask(_BaseTask):
    """A validated file_write task."""

    type: Literal["file_write"]
    params: FileWriteParams


class LogEntryTask(_BaseTask):
    """A validated log_entry task."""

    type: Literal["log_entry"]
    params: LogEntryParams


# ---------------------------------------------------------------------------
# Discriminated union
# This is the key trick. `Field(discriminator="type")` tells Pydantic:
# "look at the `type` field first, then route to the correct model."
# So "http_fetch" -> HttpFetchTask, "file_write" -> FileWriteTask, etc.
# An unknown type like "shell_exec" or "drop_table" is rejected outright
# because it doesn't match any Literal in the union.
# ---------------------------------------------------------------------------

AnyTask = Annotated[
    Union[HttpFetchTask, FileWriteTask, LogEntryTask],
    Field(discriminator="type"),
]


class TaskFeed(BaseModel):
    """The top-level feed envelope returned by the warehouse."""

    model_config = ConfigDict(extra="forbid")

    feed_version: str
    tasks: list[AnyTask]


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------

def validate_feed(raw: dict) -> TaskFeed:
    """Parse and validate a raw feed dict against the TaskFeed schema.

    Raises pydantic.ValidationError if the feed or any task is malformed.
    Callers should catch ValidationError and handle per-task failures.
    """
    return TaskFeed.model_validate(raw)
