"""Tool handler for file_write tasks.

Writes content to a file inside a sandboxed output directory.
The sandbox check runs AFTER sanitisation as a second layer of defence --
if a crafted path somehow slips past the sanitiser's allowlist regex, the
resolve() check here catches it before anything is written to disk.
"""

from pathlib import Path


# All file_write output is confined to this directory, relative to wherever
# the agent is launched from. We never write outside of it.
_SANDBOX_DIR = Path("output")


def run(path: str, content: str) -> dict:
    """Write `content` to `path` inside the sandboxed output directory.

    Args:
        path:    The relative path from the task params (already sanitised).
        content: The content to write (already sanitised).

    Returns:
        A result dict with the resolved output path.

    Raises:
        PermissionError: If the resolved path escapes the sandbox.
        OSError:         If the file cannot be written.
    """
    # Resolve the full absolute path of the intended output file.
    # Path.resolve() collapses any '..' segments and symlinks.
    sandbox = _SANDBOX_DIR.resolve()
    target = (_SANDBOX_DIR / path).resolve()

    # The critical check: is the resolved target still inside our sandbox?
    # Even if '../../etc/passwd' somehow passed the sanitiser regex, resolve()
    # would give us the real absolute path, and this check would catch it.
    if not str(target).startswith(str(sandbox)):
        raise PermissionError(
            f"Path traversal attempt blocked: '{path}' resolves outside sandbox. "
            f"Resolved to: {target}"
        )

    # Create any intermediate directories (e.g. output/reports/data.txt).
    target.parent.mkdir(parents=True, exist_ok=True)

    # Write the file. We use 'w' (text mode) with explicit UTF-8 encoding.
    # We intentionally do NOT use 'a' (append) -- overwrite is predictable,
    # append lets an attacker accumulate injected content across multiple tasks.
    target.write_text(content, encoding="utf-8")

    return {
        "written_to": str(target),
        "bytes_written": len(content.encode("utf-8")),
    }
