"""
Report Generator — renders ScanResult to terminal (Rich), JSON, and Markdown.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from src.models import GRADE_COLOR, Confidence, Finding, ScanResult, Severity

console = Console()

# Severity → emoji prefix
SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "⚪",
}

CONFIDENCE_STYLE = {
    Confidence.CONFIRMED: "bold",
    Confidence.SUSPECTED: "dim",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def print_terminal_report(result: ScanResult) -> None:
    """Print a rich terminal report to stdout."""
    _print_header(result)

    if not result.findings:
        console.print(
            Panel(
                "[bold green]✅  No security issues found![/bold green]\n"
                f"Scanned [bold]{result.files_scanned}[/bold] files in "
                f"{result.scan_duration_seconds:.2f}s",
                border_style="green",
            )
        )
        return

    _print_summary_table(result)
    _print_findings(result)
    _print_footer(result)


def write_json_report(result: ScanResult, output_path: Path) -> None:
    """Write machine-readable JSON report."""
    data = result.model_dump(mode="json")
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[dim]JSON report written to[/dim] {output_path}")


def write_markdown_report(result: ScanResult, output_path: Path) -> None:
    """Write a human-readable Markdown report."""
    lines = _build_markdown(result)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[dim]Markdown report written to[/dim] {output_path}")


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------


def _print_header(result: ScanResult) -> None:
    console.print()
    console.print(Rule("[bold]Agent Risk Analyzer[/bold]", style="dim"))
    console.print(
        f"  [dim]Target:[/dim]  {result.target_path}\n"
        f"  [dim]Files:[/dim]   {result.files_scanned} scanned  |  "
        f"[dim]Duration:[/dim] {result.scan_duration_seconds:.2f}s  |  "
        f"[dim]Framework:[/dim] {result.framework_detected or 'unknown'}"
    )
    console.print()


def _print_summary_table(result: ScanResult) -> None:
    by_sev = result.findings_by_severity

    # Grade badge
    grade_style = GRADE_COLOR.get(result.grade, "white")
    grade_text = Text(f" {result.grade} ", style=f"{grade_style} on black")

    table = Table(
        title="Scan Summary",
        show_header=True,
        header_style="bold",
        box=None,
        padding=(0, 2),
    )
    table.add_column("Grade", justify="center")
    table.add_column("Score")
    table.add_column("🔴 Critical", justify="right")
    table.add_column("🟠 High", justify="right")
    table.add_column("🟡 Medium", justify="right")
    table.add_column("⚪ Low", justify="right")
    table.add_column("Total", justify="right")

    table.add_row(
        grade_text,
        str(result.score),
        str(len(by_sev[Severity.CRITICAL])),
        str(len(by_sev[Severity.HIGH])),
        str(len(by_sev[Severity.MEDIUM])),
        str(len(by_sev[Severity.LOW])),
        str(len(result.findings)),
    )

    console.print(table)
    console.print()


def _print_findings(result: ScanResult) -> None:
    console.print(Rule("[bold]Findings[/bold]", style="dim"))
    console.print()

    current_file = None

    for finding in result.findings:
        # File header when we move to a new file
        if finding.file_path != current_file:
            current_file = finding.file_path
            console.print(f"[bold cyan]📄 {finding.file_path}[/bold cyan]")

        _print_finding(finding)

    console.print()


def _print_finding(f: Finding) -> None:
    sev_style = f.severity.color
    icon = SEVERITY_ICON[f.severity]
    conf_style = CONFIDENCE_STYLE[f.confidence]

    # Title line
    loc = f"line {f.line_number}" if f.line_number else "file-level"
    console.print(
        f"  {icon} [{sev_style}]{f.severity.value}[/{sev_style}]  "
        f"[{conf_style}]{f.confidence.value}[/{conf_style}]  "
        f"[bold]{f.title}[/bold]  "
        f"[dim]({loc})[/dim]"
    )

    # Rule IDs
    refs = f"[dim]{f.vuln_id}"
    if f.atlas_id:
        refs += f"  |  ATLAS {f.atlas_id}"
    if f.owasp_ref:
        refs += f"  |  OWASP {f.owasp_ref}"
    refs += "[/dim]"
    console.print(f"     {refs}")

    # Code snippet
    if f.code_snippet:
        console.print(f"     [on black dim]  {f.code_snippet}  [/on black dim]")

    # Fix
    console.print(f"     [green]💡 {f.fix_suggestion}[/green]")
    console.print()


def _print_footer(result: ScanResult) -> None:
    grade_style = GRADE_COLOR.get(result.grade, "white")
    grade_char = result.grade

    if grade_char in ("A", "B"):
        msg = "Good posture — review SUSPECTED findings and keep iterating."
    elif grade_char == "C":
        msg = "Needs attention — address HIGH findings before production."
    elif grade_char == "D":
        msg = "Significant risk — do not deploy without remediation."
    else:
        msg = "Unsafe for production — critical issues must be fixed immediately."

    console.print(
        Panel(
            f"[{grade_style}]Grade {grade_char}[/{grade_style}]  Score: {result.score}  —  {msg}",
            border_style=grade_style,
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _build_markdown(result: ScanResult) -> list[str]:
    lines: list[str] = []
    lines += [
        "# Agent Risk Analyzer — Security Report",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Target** | `{result.target_path}` |",
        f"| **Grade** | **{result.grade}** (score: {result.score}) |",
        f"| **Files Scanned** | {result.files_scanned} |",
        f"| **Duration** | {result.scan_duration_seconds:.2f}s |",
        f"| **Framework** | {result.framework_detected or 'unknown'} |",
        f"| **ARA Version** | {result.ara_version} |",
        "",
    ]

    by_sev = result.findings_by_severity
    lines += [
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| 🔴 Critical | {len(by_sev[Severity.CRITICAL])} |",
        f"| 🟠 High | {len(by_sev[Severity.HIGH])} |",
        f"| 🟡 Medium | {len(by_sev[Severity.MEDIUM])} |",
        f"| ⚪ Low | {len(by_sev[Severity.LOW])} |",
        f"| **Total** | **{len(result.findings)}** |",
        "",
    ]

    if not result.findings:
        lines.append("✅ No findings — clean scan!")
        return lines

    lines += ["## Findings", ""]

    current_file = None
    for f in result.findings:
        if f.file_path != current_file:
            current_file = f.file_path
            lines += [f"### 📄 `{f.file_path}`", ""]

        loc = f"Line {f.line_number}" if f.line_number else "File-level"
        lines += [
            f"#### {f.severity.value} — {f.title}",
            "",
            f"- **Rule:** {f.vuln_id}",
            f"- **Confidence:** {f.confidence.value}",
            f"- **Location:** {loc}",
        ]
        if f.atlas_id:
            lines.append(
                f"- **MITRE ATLAS:** [{f.atlas_id}](https://atlas.mitre.org/techniques/{f.atlas_id})"
            )
        if f.owasp_ref:
            lines.append(f"- **OWASP LLM:** {f.owasp_ref}:2025")

        lines += [
            "",
            f"> {f.description}",
            "",
        ]
        if f.code_snippet:
            lines += [f"```python", f"{f.code_snippet}", "```", ""]

        lines += [f"**Fix:** {f.fix_suggestion}", "", "---", ""]

    return lines
