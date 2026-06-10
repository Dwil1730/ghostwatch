import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typing import Optional

from src.probes.probe_library import PROBES, get_all_probes
from src.core.pipeline import run_scan

app = typer.Typer(help="Ghostwatch — AI Security Probe CLI")
console = Console()


@app.command()
def stats():
    """Show static probe metadata."""
    all_probes = get_all_probes()
    console.print("\n[bold]GHOSTWATCH — PROBE INVENTORY[/bold]\n")
    console.print(f"Total probes: {len(all_probes)}\n")
    for k, v in PROBES.items():
        console.print(f"  {k}: {len(v['payloads'])} payloads — {v['description']}")
    console.print()


@app.command()
def run(
    filter_type: Optional[str] = None,
    url: Optional[str] = typer.Option(None, "--url", help="Target URL to scan"),
):
    """Execute full scan and print professional summary."""
    console.print("\n[bold]GHOSTWATCH SECURITY SCAN[/bold]\n")

    result = run_scan(filter_type=filter_type, url=url)

    if result["status"] != "ok":
        console.print(f"[red]Scan failed:[/red] {result['errors']}")
        raise typer.Exit(1)

    data = result["data"]
    unique_vulnerable = data["unique_vulnerable"]

    console.print(f"  Timestamp:   {data['timestamp']}")
    console.print(f"  Probes run:  {data['total_executed']}")
    console.print(f"  Vulnerable:  [red]{data['total_vulnerable']}[/red] ({data['total_unique_vulnerable']} unique attack types)")
    console.print(f"  Safe:        [green]{data['total_safe']}[/green]")
    console.print(f"  Errors:      {data['total_errors']}")
    console.print()

    if not unique_vulnerable:
        console.print("[green]No vulnerabilities detected.[/green]\n")
        raise typer.Exit(0)

    console.print(f"[bold red]FINDINGS ({data['total_unique_vulnerable']} unique / {data['total_vulnerable']} total hits)[/bold red]\n")

    table = Table(show_header=True, header_style="bold", show_lines=True)
    table.add_column("Probe Type", style="cyan", min_width=22)
    table.add_column("Severity", min_width=10)
    table.add_column("Score", justify="right", min_width=6)
    table.add_column("Sample Payload", min_width=35)
    table.add_column("Indicators", min_width=25)
    table.add_column("MITRE", min_width=12)
    table.add_column("OWASP", min_width=8)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "white",
    }

    for r in unique_vulnerable:
        sev = r["severity"]
        color = severity_colors.get(sev, "white")
        table.add_row(
            r["probe_type"],
            Text(sev, style=color),
            str(r["risk_score"]),
            r["payload"][:40] + "..." if len(r["payload"]) > 40 else r["payload"],
            ", ".join(r["indicators"][:3]),
            r["mitre_id"],
            r["owasp_category"],
        )

    console.print(table)
    console.print()


@app.command()
def version():
    """Print version."""
    console.print("Ghostwatch v1.0")


if __name__ == "__main__":
    app()
