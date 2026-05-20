import typer
from rich.console import Console
from rich.panel import Panel
from src.modules.recon import run_recon
from src.modules.port_scanner import run_port_scan
from src.modules.vuln_checker import run_vuln_check

app = typer.Typer()
console = Console()

@app.command()
def scan(
    target: str,
    ports: bool = typer.Option(False, "--ports", help="Run port scan"),
    vuln: bool = typer.Option(False, "--vuln", help="Run vulnerability check")
):
    """Run a security scan on a target URL or IP."""
    console.print(Panel(
        f"[bold green]WWSAF Starting...[/bold green]\n"
        f"Target: [cyan]{target}[/cyan]",
        title="Windows Web Security & Audit Framework",
        border_style="green"
    ))

    run_recon(target)

    if ports:
        run_port_scan(target)

    if vuln:
        run_vuln_check(target)

if __name__ == "__main__":
    app()