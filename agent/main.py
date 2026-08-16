"""Main entry point and poll loop for the untrusted warehouse feed agent.

Polls the feed source, validates task structure, sanitises untrusted strings,
dispatches safe tasks, tracks state across cycles, and renders a live terminal UI.
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Optional

from pydantic import TypeAdapter, ValidationError
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

# Reconfigure stdout/stderr for proper UTF-8 handling on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console(force_terminal=True)

from agent.executor import execute_task, quarantine_task
from agent.parser import FeedParseError, parse_feed_file
from agent.sanitiser import sanitise_task
from agent.state import (
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_QUARANTINED,
    StateStore,
)
from agent.validator import AnyTask

console = Console()
task_adapter = TypeAdapter(AnyTask)


def process_single_task(raw_task: dict[str, Any], store: StateStore) -> None:
    """Process a single raw task through validation, sanitisation, and execution."""
    task_id = str(raw_task.get("task_id", "unknown_task"))

    # Check if task was already processed or permanently quarantined in prior cycles
    existing_record = store.get_task(task_id)
    if existing_record:
        if existing_record.status == STATUS_DONE:
            console.print(f"[dim]• Task [bold]{task_id}[/bold] already completed. Skipping (idempotent).[/dim]")
            return
        if existing_record.status == STATUS_QUARANTINED:
            console.print(f"[bold red]• Task [bold]{task_id}[/bold] is quarantined. Skipping.[/bold red]")
            return
        if existing_record.status == STATUS_FAILED:
            raw_retry_limit = raw_task.get("retry_limit", 1)
            retry_limit = int(raw_retry_limit) if isinstance(raw_retry_limit, (int, str)) and str(raw_retry_limit).isdigit() else 1
            if existing_record.attempts >= retry_limit:
                console.print(f"[bold yellow]• Task [bold]{task_id}[/bold] exceeded retry limit ({existing_record.attempts}/{retry_limit}). Escalated.[/bold yellow]")
                return

    store.record_seen(task_id)

    # -----------------------------------------------------------------------
    # Step 1: Structural Schema Validation (Pydantic)
    # -----------------------------------------------------------------------
    try:
        validated_task = task_adapter.validate_python(raw_task)
    except ValidationError as err:
        # Why this error extraction logic?
        # Pydantic's `err.errors()` returns a list of error dictionaries.
        # Each dictionary contains:
        #   - 'loc': A tuple of field names indicating WHERE the error happened
        #            (e.g. ('params', 'path') or ('type',))
        #   - 'msg': A human-readable description of WHAT went wrong (e.g. 'Field required')
        # We format each item into "location: message" strings so the logs and console
        # give operators exact actionable diagnostics instead of generic failure messages.
        errors = [f"{e['loc']}: {e['msg']}" for e in err.errors()]
        console.print(f"[bold red]❌ REJECTED [bold]{task_id}[/bold]: Schema validation failed.[/bold red]")
        for err_msg in errors:
            console.print(f"   [red]↳ {err_msg}[/red]")
        
        # Safely quarantine the invalid task to SQLite and the audit log, then return early
        quarantine_task(task_id, raw_task, errors, store)
        return

    # -----------------------------------------------------------------------
    # Step 2: Content Sanitisation & Injection Detection (Allowlist + Blocklist)
    # -----------------------------------------------------------------------
    sanitisation_result = sanitise_task(validated_task)
    if not sanitisation_result.is_clean:
        console.print(f"[bold red]🛡️ QUARANTINED [bold]{task_id}[/bold]: Malicious content / injection detected.[/bold red]")
        for violation in sanitisation_result.violations:
            console.print(f"   [yellow]↳ {escape(violation)}[/yellow]")
        quarantine_task(task_id, raw_task, sanitisation_result.violations, store)
        return

    # -----------------------------------------------------------------------
    # Step 3: Safe Orchestration and Execution
    # -----------------------------------------------------------------------
    console.print(f"[bold cyan]⚙️ EXECUTING [bold]{task_id}[/bold] (type: {validated_task.type}, priority: {validated_task.priority})...[/bold cyan]")
    exec_result = execute_task(validated_task, store)

    if exec_result.success:
        console.print(f"[bold green]✅ COMPLETED [bold]{task_id}[/bold]: Result recorded.[/bold green]")
        if exec_result.result:
            console.print(f"   [dim green]Result: {exec_result.result}[/dim green]")
    else:
        if exec_result.escalated:
            console.print(f"[bold red]🚨 ESCALATED [bold]{task_id}[/bold]: Execution failed and reached max retries ({exec_result.error})[/bold red]")
        else:
            console.print(f"[bold yellow]⚠️ RETRY QUEUED [bold]{task_id}[/bold]: Execution failed ({exec_result.error})[/bold yellow]")


def render_state_table(store: StateStore) -> None:
    """Render a visual summary table of all known task states."""
    records = store.get_all_tasks()
    if not records:
        return

    table = Table(title="Agent Persistent State", header_style="bold magenta", show_lines=True)
    table.add_column("Task ID", style="bold", justify="left")
    table.add_column("Status", justify="center")
    table.add_column("Attempts", justify="right")
    table.add_column("Last Seen (UTC)", justify="center")
    # Iterate over each SQLite record, color-code status badges (green=done,
    # red=quarantined, yellow=failed), format UTC timestamps, and truncate long
    # output strings to keep the terminal table clean and readable on screen.
    for r in records:
        status_formatted = r.status.upper()
        if r.status == STATUS_DONE:
            status_formatted = f"[bold green]{status_formatted}[/bold green]"
            detail = str(r.result) if r.result else "Success"
        elif r.status == STATUS_QUARANTINED:
            status_formatted = f"[bold red]{status_formatted}[/bold red]"
            detail = f"[red]{r.error}[/red]"
        elif r.status == STATUS_FAILED:
            status_formatted = f"[bold yellow]{status_formatted}[/bold yellow]"
            detail = f"[yellow]{r.error}[/yellow]"
        else:
            status_formatted = f"[cyan]{status_formatted}[/cyan]"
            detail = "Pending"

        table.add_row(
            r.task_id,
            status_formatted,
            str(r.attempts),
            r.last_seen.split("T")[1][:8] if "T" in r.last_seen else r.last_seen,
            (detail[:70] + "...") if len(detail) > 70 else detail,
        )

    console.print(table)


def run_agent(
    feed_path: str,
    db_path: str,
    poll_interval: float,
    max_cycles: Optional[int] = None,
) -> None:
    """Run the agent polling loop."""
    console.print(
        Panel.fit(
            f"[bold green]LEC AI Untrusted Feed Agent[/bold green]\n"
            f"[dim]Feed Source:[/dim] {feed_path}\n"
            f"[dim]State Database:[/dim] {db_path}\n"
            f"[dim]Poll Interval:[/dim] {poll_interval}s\n"
            f"[dim]Max Cycles:[/dim] {max_cycles if max_cycles else 'Continuous'}",
            title="Agent Initialised",
            border_style="green",
        )
    )

    cycle = 1
    with StateStore(db_path) as store:
        while True:
            console.rule(f"[bold blue]Poll Cycle #{cycle}[/bold blue]")

            try:
                feed_version, raw_tasks = parse_feed_file(feed_path)
                console.print(f"[dim]Fetched feed version {feed_version} ({len(raw_tasks)} tasks found).[/dim]\n")

                # Dynamic execution ordering: sort by priority (lower number = higher priority)
                def sort_key(item: dict[str, Any]) -> int:
                    priority = item.get("priority", 99)
                    return priority if isinstance(priority, int) else 99

                sorted_tasks = sorted(raw_tasks, key=sort_key)

                # Process tasks dynamically in priority order. If any single task fails
                # validation, contains an injection, or errors during execution, it is
                # quarantined or flagged without stopping the loop from processing the others.
                for raw_task in sorted_tasks:
                    process_single_task(raw_task, store)

            except FeedParseError as err:
                console.print(f"[bold red]⚠️ Feed Ingestion Error: {err}[/bold red]")

            console.print("")
            render_state_table(store)

            if max_cycles is not None and cycle >= max_cycles:
                console.print(f"\n[bold green]Finished requested {max_cycles} poll cycle(s). Exiting cleanly.[/bold green]")
                break

            cycle += 1
            console.print(f"\n[dim]Sleeping {poll_interval}s until next poll cycle... (Press Ctrl+C to stop)[/dim]")
            time.sleep(poll_interval)


def main() -> None:
    """CLI parser and entry point."""
    parser = argparse.ArgumentParser(
        description="Autonomous agent for consuming and safely executing tasks from untrusted feeds."
    )
    parser.add_argument(
        "--feed",
        type=str,
        default="feed/tasks.json",
        help="Path to the tasks JSON feed file (default: feed/tasks.json)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="agent_state.db",
        help="Path to the SQLite state database file (default: agent_state.db)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Seconds to wait between feed polls (default: 5.0)",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=None,
        help="Number of poll cycles to run before exiting (default: run indefinitely)",
    )

    args = parser.parse_args()

    try:
        run_agent(
            feed_path=args.feed,
            db_path=args.db,
            poll_interval=args.poll_interval,
            max_cycles=args.cycles,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Agent interrupted by user. Shutting down safely.[/bold yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
