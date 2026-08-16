"""Tool handler for log_entry tasks.

Appends a structured JSON line to logs/execution.jsonl.
JSONL (JSON Lines) format means one JSON object per line -- easy to tail,
easy to parse with any log aggregator, and safe to append to concurrently.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


_LOG_FILE = Path("logs") / "execution.jsonl"


def run(message: str, level: str) -> dict:
    """Append a log entry to the execution log.

    Args:
        message: The log message (already sanitised).
        level:   The log level -- INFO, WARNING, or ERROR (already validated).

    Returns:
        A result dict confirming what was logged and where.
    """
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
    }

    # 'a' (append) mode: each call adds one line, never overwrites.
    # ensure_ascii=True: keeps the file pure ASCII -- no surprise unicode
    # escape sequences that could confuse downstream log parsers.
    with _LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")

    return {
        "logged_to": str(_LOG_FILE),
        "level": level,
        "message": message,
    }
