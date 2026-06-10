"""Render triage results as a ranked analyst queue."""
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .triage import TriageResult, Severity

SEVERITY_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.informational: 4,
}
SEVERITY_STYLE = {
    Severity.critical: "bold white on red",
    Severity.high: "bold red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.informational: "dim",
}
SEVERITY_BORDER = {
    Severity.critical: "red",
    Severity.high: "red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.informational: "dim",
}


def rank(results: List[TriageResult]) -> List[TriageResult]:
    return sorted(results, key=lambda r: (SEVERITY_ORDER[r.severity], -r.confidence))


def print_report(results: List[TriageResult], engine: str) -> None:
    console = Console()
    ranked = rank(results)

    table = Table(title=f"SSH Alert Triage Queue  (engine: {engine})",
                  show_lines=False, expand=False)
    table.add_column("#", justify="right")
    table.add_column("Source IP")
    table.add_column("Severity")
    table.add_column("Verdict")
    table.add_column("Conf.", justify="right")
    table.add_column("ATT&CK")

    for i, r in enumerate(ranked, 1):
        table.add_row(
            str(i), r.src_ip,
            f"[{SEVERITY_STYLE[r.severity]}]{r.severity.value.upper()}[/]",
            r.verdict.value.replace("_", " "),
            f"{r.confidence}%",
            r.mitre_technique_id,
        )
    console.print(table)

    for i, r in enumerate(ranked, 1):
        body = r.summary + "\n\n[bold]Recommended actions:[/bold]\n"
        body += "\n".join(f"  {n}. {a}" for n, a in enumerate(r.recommended_actions, 1))
        console.print(Panel(
            body,
            title=f"#{i}  {r.src_ip}  —  {r.severity.value.upper()} "
                  f"({r.mitre_technique_id} {r.mitre_technique_name})",
            border_style=SEVERITY_BORDER[r.severity],
        ))
