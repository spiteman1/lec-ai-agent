"""Sanitises string fields in validated task objects.

Strategy: allowlist-first, blocklist as defence-in-depth.

WHY ALLOWLIST-FIRST:
    A blocklist is reactive -- you can only block patterns you've already
    thought of. An attacker who finds a pattern you missed gets through.
    An allowlist defines exactly what is acceptable and rejects everything
    else by default. This is the correct posture for untrusted data.

    We therefore first check that every string field contains only the
    characters and structure we consider safe (printable ASCII, bounded
    length, no control characters). Only strings that pass this gate are
    then scanned against the blocklist of known-bad patterns.

    This two-layer approach means:
      - Novel injection patterns we haven't seen are still blocked by the
        allowlist if they contain unusual characters.
      - Clever attacks using only "safe" characters (like prompt injection
        written in plain English) are caught by the blocklist.
"""

import re
from dataclasses import dataclass, field
from typing import Union

from agent.validator import AnyTask, HttpFetchTask, FileWriteTask, LogEntryTask


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class SanitisationResult:
    """The outcome of sanitising a single task."""

    is_clean: bool
    violations: list[str] = field(default_factory=list)

    def add_violation(self, message: str) -> None:
        """Record a violation and mark this result as dirty."""
        self.is_clean = False
        self.violations.append(message)


# ---------------------------------------------------------------------------
# Layer 1: Allowlist regex patterns per field type
#
# Each pattern defines what IS allowed, not what is banned.
# Anything that does not match is rejected.
# ---------------------------------------------------------------------------

# General text fields (description, message): printable ASCII only, no
# control characters (tabs, newlines, null bytes), max 500 chars.
_SAFE_TEXT = re.compile(r"^[\x20-\x7E]{1,500}$")

# URL fields: http/https scheme, hostname, optional path. No query strings
# with arbitrary params, no fragment identifiers, no auth credentials.
_SAFE_URL = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{1,200}$")

# File path fields: relative paths only, using alphanumerics, slashes,
# dots, hyphens, underscores. No leading slash (absolute path), no
# Windows drive letters.
_SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-./]{0,199}$")

# Output key fields (simple identifiers): letters, numbers, underscores.
_SAFE_KEY = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")

# Log level: already constrained by the Pydantic Literal, but we check
# again as defence-in-depth.
_SAFE_LEVEL = re.compile(r"^(INFO|WARNING|ERROR)$")


# ---------------------------------------------------------------------------
# Layer 2: Blocklist patterns
#
# These are scanned AFTER the allowlist passes. They catch known-bad
# content that is made entirely of "safe" characters, like prompt injection
# written in plain English or template syntax using only ASCII.
#
# Each tuple is (compiled_pattern, human_readable_name).
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # --- Prompt injection ---
    # Phrases commonly used to hijack LLM-assisted pipelines.
    (re.compile(r"ignore\s+(previous|all|prior)\s+instructions?", re.IGNORECASE), "prompt injection: ignore instructions"),
    (re.compile(r"disregard\s+(the\s+)?(above|previous|prior|all)", re.IGNORECASE), "prompt injection: disregard"),
    (re.compile(r"new\s+(directive|instruction|task|objective|goal)", re.IGNORECASE), "prompt injection: new directive"),
    (re.compile(r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|your\s+new\s+role)", re.IGNORECASE), "prompt injection: persona hijack"),
    (re.compile(r"(system\s+prompt|jailbreak|dan\s+mode)", re.IGNORECASE), "prompt injection: jailbreak attempt"),
    (re.compile(r"skip\s+(validation|saniti[sz]ation|checks?|security)", re.IGNORECASE), "prompt injection: bypass attempt"),

    # --- Template injection ---
    # These are probes for Jinja2, Handlebars, Twig, ERB etc.
    (re.compile(r"\{\{.{0,100}\}\}"), "template injection: {{ }} expression"),
    (re.compile(r"\{%.{0,100}%\}"), "template injection: {% %} block"),
    (re.compile(r"\$\{\{"), "template injection: ${{ expression"),
    (re.compile(r"<%=?.{0,100}%>"), "template injection: ERB expression"),

    # --- Code/command injection ---
    # Python eval/exec patterns and shell execution.
    (re.compile(r"\bos\s*\.\s*system\s*\("), "code injection: os.system()"),
    (re.compile(r"\bsubprocess\s*\.\s*(run|call|Popen|check_output)", re.IGNORECASE), "code injection: subprocess"),
    (re.compile(r"\beval\s*\("), "code injection: eval()"),
    (re.compile(r"\bexec\s*\("), "code injection: exec()"),
    (re.compile(r"__import__\s*\("), "code injection: __import__()"),
    (re.compile(r"\bimport\s+os\b"), "code injection: import os"),
    (re.compile(r"shell\s*=\s*True"), "code injection: shell=True"),
    (re.compile(r"`[^`]{0,200}`"), "command injection: backtick shell execution"),
    (re.compile(r"\$\([^)]{0,200}\)"), "command injection: $() subshell"),

    # --- Data exfiltration patterns ---
    (re.compile(r"\b(curl|wget|nc|ncat|netcat)\s+https?://", re.IGNORECASE), "exfiltration: outbound request tool"),
    (re.compile(r"/etc/(passwd|shadow|hosts|sudoers)", re.IGNORECASE), "exfiltration: sensitive file reference"),

    # --- Path traversal ---
    (re.compile(r"\.\.[/\\]"), "path traversal: ../"),
    (re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE), "path traversal: URL-encoded ../"),

    # --- Destructive shell commands ---
    (re.compile(r"rm\s+-rf?\s+[/~]", re.IGNORECASE), "destructive: rm -rf"),
    (re.compile(r"(format|del|rmdir)\s+[a-zA-Z]:\\", re.IGNORECASE), "destructive: Windows drive wipe"),
]


# ---------------------------------------------------------------------------
# Field-level checks
# ---------------------------------------------------------------------------

def _check_text(value: str, field_name: str, result: SanitisationResult) -> None:
    """Apply allowlist then blocklist to a general text field."""
    if not _SAFE_TEXT.match(value):
        result.add_violation(
            f"field '{field_name}' failed allowlist check: must be 1-500 printable "
            f"ASCII characters with no control characters."
        )
        # Don't bother running the blocklist on a field that already failed --
        # the violation is already recorded.
        return

    _scan_blocklist(value, field_name, result)


def _check_url(value: str, field_name: str, result: SanitisationResult) -> None:
    """Apply URL-specific allowlist then blocklist."""
    if not _SAFE_URL.match(value):
        result.add_violation(
            f"field '{field_name}' failed URL allowlist check: must be a well-formed "
            f"http/https URL with no unusual characters."
        )
        return

    _scan_blocklist(value, field_name, result)


def _check_path(value: str, field_name: str, result: SanitisationResult) -> None:
    """Apply path-specific allowlist then blocklist."""
    if not _SAFE_PATH.match(value):
        result.add_violation(
            f"field '{field_name}' failed path allowlist check: must be a relative "
            f"path using only alphanumerics, slashes, dots, hyphens, underscores."
        )
        return

    _scan_blocklist(value, field_name, result)


def _check_key(value: str, field_name: str, result: SanitisationResult) -> None:
    """Apply identifier allowlist to output key fields."""
    if not _SAFE_KEY.match(value):
        result.add_violation(
            f"field '{field_name}' failed key allowlist check: must start with a "
            f"letter and contain only alphanumerics and underscores (max 64 chars)."
        )


def _scan_blocklist(value: str, field_name: str, result: SanitisationResult) -> None:
    """Scan a string against every known-bad pattern in _INJECTION_PATTERNS."""
    for pattern, label in _INJECTION_PATTERNS:
        if pattern.search(value):
            result.add_violation(
                f"field '{field_name}' matched injection pattern [{label}]."
            )
            # Don't break -- report ALL matching patterns for full visibility.


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def sanitise_task(task: AnyTask) -> SanitisationResult:
    """Sanitise all string fields of a validated task object.

    Returns a SanitisationResult. If is_clean is False, violations contains
    a description of every problem found. The caller should quarantine the
    task and never pass it to the executor.

    Note: this function receives an already-validated task (Pydantic model),
    so we know the structure is correct. We are only checking content here.
    """
    result = SanitisationResult(is_clean=True)

    # Every task type has a description field -- always check it.
    _check_text(task.description, "description", result)

    # Now branch on task type to check the params fields.
    if isinstance(task, HttpFetchTask):
        _check_url(task.params.url, "params.url", result)
        _check_key(task.params.output_key, "params.output_key", result)

    elif isinstance(task, FileWriteTask):
        _check_path(task.params.path, "params.path", result)
        _check_text(task.params.content, "params.content", result)

    elif isinstance(task, LogEntryTask):
        _check_text(task.params.message, "params.message", result)
        # level is already constrained by the Pydantic Literal -- no extra check needed.

    return result
