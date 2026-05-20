import typer
from rich.console import Console
from rich.panel import Panel
from src.modules.recon import run_recon
from src.modules.port_scanner import run_port_scan
from src.modules.vuln_checker import run_vuln_check
from src.modules.reporter import generate_report

app = typer.Typer()
console = Console()

@app.command()
def scan(
    target: str,
    ports: bool = typer.Option(False, "--ports", help="Run port scan"),
    vuln: bool = typer.Option(False, "--vuln", help="Run vulnerability check"),
    report: bool = typer.Option(False, "--report", help="Generate HTML report")
):
    """Run a security scan on a target URL or IP."""
    console.print(Panel(
        f"[bold green]WWSAF Starting...[/bold green]\n"
        f"Target: [cyan]{target}[/cyan]",
        title="Windows Web Security & Audit Framework",
        border_style="green"
    ))

    recon_data = run_recon(target)
    port_data = []
    vuln_data = []

    if ports:
        port_data = run_port_scan(target)

    if vuln:
        vuln_data = run_vuln_check(target)

    if report:
        filename = generate_report(target, recon_data, port_data, vuln_data)
        console.print(f"\n[bold green]Report saved:[/bold green] {filename}")

if __name__ == "__main__":
    app()