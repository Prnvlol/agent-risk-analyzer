"""
ARA CLI — entry point for all commands.

Commands:
  ara scan <path>       Run a full security scan
  ara list-rules        List all detection rules
  ara version           Print ARA version
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from src import __version__
from src.models import ScanConfig, Severity

app = typer.Typer(
    name="ara",
    help="Agent Risk Analyzer — static security scanner for AI agents.",
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# ara scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: Path = typer.Argument(
        ...,
        help="Path to the agent project directory to scan.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
    ),
    format: str = typer.Option(
        "terminal",
        "--format", "-f",
        help="Output format: terminal | json | markdown",
    ),
    output: Path | None = typer.Option(
        None,
        "--output", "-o",
        help="Write report to this file (required for json/markdown formats).",
    ),
    min_severity: str = typer.Option(
        "LOW",
        "--min-severity", "-s",
        help="Minimum severity to report: CRITICAL | HIGH | MEDIUM | LOW",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode — exit code 1 if any findings match min-severity.",
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable optional LLM-powered semantic analysis (requires ollama or API key).",
    ),
    no_suspected: bool = typer.Option(
        False,
        "--no-suspected",
        help="Only show CONFIRMED findings (hide heuristic/absence checks).",
    ),
    disable: str | None = typer.Option(
        None,
        "--disable",
        help="Comma-separated list of rule IDs or detector names to disable.",
    ),
) -> None:
    """Scan an AI agent project for security vulnerabilities."""

    # Validate format
    valid_formats = {"terminal", "json", "markdown"}
    if format not in valid_formats:
        err_console.print(f"[red]Error:[/red] --format must be one of: {', '.join(valid_formats)}")
        raise typer.Exit(2)

    if format in ("json", "markdown") and output is None:
        err_console.print(
            f"[red]Error:[/red] --output <file> is required when using --format {format}"
        )
        raise typer.Exit(2)

    # Parse severity
    try:
        min_sev = Severity(min_severity.upper())
    except ValueError:
        err_console.print(
            "[red]Error:[/red] --min-severity must be one of: CRITICAL, HIGH, MEDIUM, LOW"
        )
        raise typer.Exit(2)

    # Parse disabled rules
    disabled_rules: list[str] = []
    if disable:
        disabled_rules = [r.strip() for r in disable.split(",") if r.strip()]

    config = ScanConfig(
        target_path=target.resolve(),
        output_format=format,
        output_file=output,
        min_severity=min_sev,
        ci_mode=ci,
        deep=deep,
        disabled_rules=disabled_rules,
        include_suspected=not no_suspected,
    )

    # Run scan
    from src.report import print_terminal_report, write_json_report, write_markdown_report
    from src.scanner import Scanner

    console.print(f"[dim]🔍 Scanning[/dim] [bold]{target}[/bold] [dim]...[/dim]")

    try:
        result = Scanner(config).run()
    except Exception as exc:
        err_console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(2)

    # Render output
    if format == "terminal":
        print_terminal_report(result)
    elif format == "json":
        write_json_report(result, output)  # type: ignore[arg-type]
    elif format == "markdown":
        write_markdown_report(result, output)  # type: ignore[arg-type]
        print_terminal_report(result)  # also show terminal summary

    # CI exit code
    if ci and result.findings:
        raise typer.Exit(1)

    raise typer.Exit(0)


# ---------------------------------------------------------------------------
# ara list-rules
# ---------------------------------------------------------------------------


@app.command(name="list-rules")
def list_rules(
    format: str = typer.Option("table", "--format", "-f", help="table | json"),
) -> None:
    """List all detection rules with their ATLAS and OWASP mappings."""
    from src.detectors import ALL_DETECTORS

    if format == "json":
        import json as _json
        rules = []
        for detector in ALL_DETECTORS:
            rules.append({
                "detector": detector.name,
                "description": detector.description,
                "vuln_ids": detector.vuln_ids,
            })
        console.print(_json.dumps(rules, indent=2))
        return

    table = Table(
        title="ARA Detection Rules",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Detector", style="cyan")
    table.add_column("Vuln IDs")
    table.add_column("Description")

    for detector in ALL_DETECTORS:
        table.add_row(
            detector.name,
            ", ".join(detector.vuln_ids),
            detector.description,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# ara version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the ARA version."""
    console.print(f"Agent Risk Analyzer [bold]{__version__}[/bold]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    app()


if __name__ == "__main__":
    main()
