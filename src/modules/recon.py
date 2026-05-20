import httpx
from rich.console import Console
from rich.table import Table
import time

console = Console()

def run_recon(target: str):
    console.print(f"\n[bold cyan]Starting recon on:[/bold cyan] {target}\n")

    # --- Step 1: Send HTTP request and measure time ---
    try:
        start = time.time()
        response = httpx.get(target, follow_redirects=True, timeout=10)
        elapsed = round((time.time() - start) * 1000, 2)
    except httpx.RequestError as e:
        console.print(f"[bold red]Connection failed:[/bold red] {e}")
        return

    # --- Step 2: Build results table ---
    table = Table(title="Recon Results", border_style="cyan")
    table.add_column("Property", style="bold white")
    table.add_column("Value", style="green")

    table.add_row("Target URL", str(response.url))
    table.add_row("Status Code", str(response.status_code))
    table.add_row("Response Time", f"{elapsed} ms")

    # --- Step 3: Detect server from headers ---
    server = response.headers.get("server", "Not disclosed")
    powered_by = response.headers.get("x-powered-by", "Not disclosed")
    content_type = response.headers.get("content-type", "Unknown")

    table.add_row("Server", server)
    table.add_row("Powered By", powered_by)
    table.add_row("Content Type", content_type)

    # --- Step 4: Security headers check ---
    security_headers = [
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "referrer-policy"
    ]

    missing = []
    present = []

    for header in security_headers:
        if header in response.headers:
            present.append(header)
        else:
            missing.append(header)

    table.add_row("Security Headers OK", str(len(present)))
    table.add_row("Security Headers Missing", str(len(missing)))

    console.print(table)

    # --- Step 5: Show missing headers as warnings ---
    if missing:
        console.print("\n[bold red]Missing Security Headers:[/bold red]")
        for h in missing:
            console.print(f"  [red]✗[/red] {h}")

    if present:
        console.print("\n[bold green]Present Security Headers:[/bold green]")
        for h in present:
            console.print(f"  [green]✓[/green] {h}")