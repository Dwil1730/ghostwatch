import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typing import Optional
import json

from reportlab.pdfgen import canvas

from src.probes.probe_library import PROBES, get_all_probes
from src.core.pipeline import run_scan

app = typer.Typer(help="Ghostwatch — AI Security Probe CLI")
console = Console()


# =========================
# PROBE INVENTORY COMMAND
# =========================
@app.command()
def stats():
    """Show static probe metadata."""
    all_probes = get_all_probes()

    console.print("\n[bold]GHOSTWATCH — PROBE INVENTORY[/bold]\n")
    console.print(f"Total probes: {len(all_probes)}\n")

    for k, v in PROBES.items():
        console.print(f"  {k}: {len(v['payloads'])} payloads — {v['description']}")

    console.print()


# =========================
# MAIN SCAN COMMAND (UPGRADED)
# =========================
@app.command()
def run(
    filter_type: Optional[str] = None,
    url: Optional[str] = None,
    method: str = "POST",
    export: Optional[str] = typer.Option(None, help="json | pdf export format"),
):
    """Execute full scan and print professional summary."""

    console.print("\n[bold]GHOSTWATCH SECURITY SCAN[/bold]\n")

    # Run scan engine (UNCHANGED CORE BEHAVIOR)
    result = run_scan(
        filter_type=filter_type,
        url=url,
        method=method
    )

    if result["status"] != "ok":
        console.print(f"[red]Scan failed:[/red] {result['errors']}")
        raise typer.Exit(1)

    data = result["data"]
    results = data["results"]

    # =========================
    # LIVE SUMMARY OUTPUT (UNCHANGED DISPLAY STYLE)
    # =========================
    console.print(f"  Timestamp:   {data['timestamp']}")
    console.print(f"  Probes run:  {data['total_executed']}")
    console.print(f"  Vulnerable:  [red]{data['total_vulnerable']}[/red]")
    console.print(f"  Safe:        [green]{data['total_safe']}[/green]")
    console.print(f"  Errors:      {data['total_errors']}")
    console.print()

    vulnerable = [r for r in results if r["detection_status"] == "vulnerable"]

    if not vulnerable:
        console.print("[green]No vulnerabilities detected.[/green]\n")

        # still allow export even on clean scans
        summary = {
            "target": url,
            "status": "clean",
            "probes": data["total_executed"],
            "vulnerable": 0,
            "safe": data["total_safe"],
            "errors": data["total_errors"],
        }

        _handle_export(summary, export)
        raise typer.Exit(0)

    console.print(f"[bold red]FINDINGS ({len(vulnerable)})[/bold red]\n")

    # =========================
    # TABLE OUTPUT (UNCHANGED)
    # =========================
    table = Table(show_header=True, header_style="bold", show_lines=True)
    table.add_column("Probe", style="cyan", min_width=22)
    table.add_column("Severity", min_width=10)
    table.add_column("Score", justify="right", min_width=6)
    table.add_column("Indicators", min_width=30)
    table.add_column("MITRE", min_width=12)
    table.add_column("OWASP", min_width=8)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "white",
    }

    for r in vulnerable:
        sev = r["severity"]
        color = severity_colors.get(sev, "white")

        table.add_row(
            r["probe_type"],
            Text(sev, style=color),
            str(r["risk_score"]),
            ", ".join(r["indicators"]),
            r["mitre_id"],
            r["owasp_category"],
        )

    console.print(table)
    console.print()

    # =========================
    # NEW: STRUCTURED SUMMARY LAYER (JOEL LAYER)
    # =========================
    summary = {
        "target": url,
        "timestamp": data["timestamp"],
        "probes": data["total_executed"],
        "vulnerable": data["total_vulnerable"],
        "safe": data["total_safe"],
        "errors": data["total_errors"],
        "findings": len(vulnerable),
    }

    _handle_export(summary, export)


# =========================
# EXPORT LAYER (SAFE ADD-ON)
# =========================
def _handle_export(summary, export_type: Optional[str]):
    if export_type == "json":
        with open("ghostwatch_report.json", "w") as f:
            json.dump(summary, f, indent=2)

        console.print("[green]JSON report generated: ghostwatch_report.json[/green]")

    elif export_type == "pdf":
        export_pdf(summary)
        console.print("[green]PDF report generated: ghostwatch_report.pdf[/green]")


# =========================
# PDF GENERATOR (ADD-ON ONLY)
# =========================
def export_pdf(summary):
    c = canvas.Canvas("ghostwatch_report.pdf")

    c.setFont("Helvetica-Bold", 14)
    c.drawString(100, 800, "GHOSTWATCH SECURITY REPORT")

    c.setFont("Helvetica", 11)

    y = 760
    for k, v in summary.items():
        c.drawString(100, y, f"{k}: {v}")
        y -= 20

    c.save()


# =========================
# VERSION
# =========================
@app.command()
def version():
    """Print version."""
    console.print("Ghostwatch v0.1")


if __name__ == "__main__":
    app()
