import httpx
from rich.console import Console
from rich.table import Table

console = Console()

# Sensitive paths to probe
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/admin",
    "/admin/login",
    "/backup.zip",
    "/config.php",
    "/database.sql",
    "/debug",
    "/login",
    "/phpmyadmin",
    "/robots.txt",
    "/server-status",
    "/test",
    "/uploads",
    "/wp-admin",
    "/wp-login.php",
]

# Headers that indicate vulnerability
VULN_HEADERS = {
    "x-powered-by": "Technology disclosure — reveals backend stack",
    "server": "Server disclosure — reveals server software",
    "x-aspnet-version": "ASP.NET version disclosed",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosed",
}

def check_https_redirect(target: str, client: httpx.Client):
    """Check if HTTP redirects to HTTPS."""
    findings = []
    if target.startswith("http://"):
        try:
            response = client.get(target, follow_redirects=False)
            location = response.headers.get("location", "")
            if response.status_code in [301, 302] and location.startswith("https://"):
                findings.append(("HTTPS Redirect", "INFO", "HTTP correctly redirects to HTTPS"))
            else:
                findings.append(("HTTPS Redirect", "HIGH", "HTTP does not redirect to HTTPS"))
        except Exception:
            findings.append(("HTTPS Redirect", "ERROR", "Could not check redirect"))
    return findings

def check_sensitive_paths(base_url: str, client: httpx.Client):
    """Probe for sensitive files and directories."""
    findings = []
    base = base_url.rstrip("/")

    console.print("[white]Probing sensitive paths...[/white]")

    for path in SENSITIVE_PATHS:
        try:
            url = base + path
            response = client.get(url, follow_redirects=False)

            if response.status_code == 200:
                findings.append((path, "HIGH", f"Accessible! Status: 200"))
            elif response.status_code == 403:
                findings.append((path, "MEDIUM", "Forbidden but exists (403)"))
            elif response.status_code == 301 or response.status_code == 302:
                findings.append((path, "LOW", f"Redirects to: {response.headers.get('location', '?')}"))
        except Exception:
            pass

    return findings

def check_information_disclosure(response_headers: dict):
    """Check headers for information disclosure."""
    findings = []
    for header, description in VULN_HEADERS.items():
        value = response_headers.get(header)
        if value:
            findings.append((header, "MEDIUM", f"{description} → [{value}]"))
    return findings

def check_security_txt(base_url: str, client: httpx.Client):
    """Check if security.txt exists (good practice indicator)."""
    findings = []
    try:
        url = base_url.rstrip("/") + "/.well-known/security.txt"
        response = client.get(url, follow_redirects=True)
        if response.status_code == 200:
            findings.append(("security.txt", "INFO", "Present — good security practice"))
        else:
            findings.append(("security.txt", "LOW", "Missing — recommended by RFC 9116"))
    except Exception:
        pass
    return findings

def run_vuln_check(target: str):
    console.print(f"\n[bold cyan]Starting vulnerability check on:[/bold cyan] {target}\n")

    all_findings = []

    with httpx.Client(timeout=10, verify=False) as client:
        # Run initial request
        try:
            response = client.get(target, follow_redirects=True)
        except httpx.RequestError as e:
            console.print(f"[bold red]Connection failed:[/bold red] {e}")
            return

        # Run all checks
        all_findings += check_https_redirect(target, client)
        all_findings += check_information_disclosure(dict(response.headers))
        all_findings += check_sensitive_paths(target, client)
        all_findings += check_security_txt(target, client)

    # --- Display results table ---
    table = Table(title="Vulnerability Findings", border_style="cyan")
    table.add_column("Finding", style="bold white", min_width=20)
    table.add_column("Severity", style="bold", min_width=10)
    table.add_column("Detail", style="white", min_width=30)

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for finding, severity, detail in all_findings:
        if severity == "HIGH":
            sev_display = "[red]HIGH[/red]"
            severity_counts["HIGH"] += 1
        elif severity == "MEDIUM":
            sev_display = "[yellow]MEDIUM[/yellow]"
            severity_counts["MEDIUM"] += 1
        elif severity == "LOW":
            sev_display = "[blue]LOW[/blue]"
            severity_counts["LOW"] += 1
        else:
            sev_display = "[green]INFO[/green]"
            severity_counts["INFO"] += 1

        table.add_row(finding, sev_display, detail)

    console.print(table)

    # --- Summary ---
    console.print(f"\n[bold]Scan Summary:[/bold]")
    console.print(f"  [red]High:  {severity_counts['HIGH']}[/red]")
    console.print(f"  [yellow]Medium: {severity_counts['MEDIUM']}[/yellow]")
    console.print(f"  [blue]Low:   {severity_counts['LOW']}[/blue]")
    console.print(f"  [green]Info:  {severity_counts['INFO']}[/green]")