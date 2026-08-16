"""Parser for untrusted warehouse task feed files.

Reads and decodes the feed JSON, treating all fetched content strictly as inert data.
"""

import json
from pathlib import Path
from typing import Any


class FeedParseError(Exception):
    """Raised when the raw feed file cannot be read or parsed as JSON."""


def parse_feed_file(file_path: str | Path) -> tuple[str, list[dict[str, Any]]]:
    """Read a JSON feed file and return its version and raw task definitions.

    Args:
        file_path: Path to the JSON feed file.

    Returns:
        A tuple of (feed_version, list_of_raw_task_dicts).

    Raises:
        FeedParseError: If the file is missing, contains invalid JSON, or lacks
                        expected top-level envelope fields.
    """
    path = Path(file_path)

    if not path.exists():
        raise FeedParseError(f"Feed file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"Malformed JSON in feed file {path}: {exc}") from exc
    except OSError as exc:
        raise FeedParseError(f"I/O error reading feed file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise FeedParseError(
            f"Invalid feed envelope in {path}: expected JSON object at root, got {type(data).__name__}"
        )

    feed_version = str(data.get("feed_version", "unknown"))
    raw_tasks = data.get("tasks", [])

    if not isinstance(raw_tasks, list):
        raise FeedParseError(
            f"Invalid tasks list in {path}: expected array, got {type(raw_tasks).__name__}"
        )

    # Filter down to dict elements; any non-dict items will fail schema validation later
    task_dicts: list[dict[str, Any]] = [t for t in raw_tasks if isinstance(t, dict)]

    return feed_version, task_dicts
