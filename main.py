import typer
from rich.console import Console
from rich.panel import Panel
from src.modules.recon import run_recon

app = typer.Typer()
console = Console()

@app.command()
def scan(target: str):
    """Run a security scan on a target URL or IP."""
    console.print(Panel(
        f"[bold green]WWSAF Starting...[/bold green]\n"
        f"Target: [cyan]{target}[/cyan]",
        title="Windows Web Security & Audit Framework",
        border_style="green"
    ))
    run_recon(target)

if __name__ == "__main__":
    app()