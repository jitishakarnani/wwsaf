import socket
import concurrent.futures
from rich.console import Console
from rich.table import Table
import time

console = Console()

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

def scan_port(host: str, port: int, timeout: float = 1.0):
    """Try to connect to a single port. Returns True if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except socket.error:
        return port, False

def resolve_host(target: str):
    """Convert domain name to IP address."""
    try:
        # Strip http:// or https:// if present
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(host)
        return host, ip
    except socket.gaierror as e:
        console.print(f"[bold red]Could not resolve host:[/bold red] {e}")
        return None, None

def run_port_scan(target: str):
    console.print(f"\n[bold cyan]Starting port scan on:[/bold cyan] {target}\n")

    # --- Step 1: Resolve hostname to IP ---
    host, ip = resolve_host(target)
    if not host:
        return

    console.print(f"[white]Resolved:[/white] [green]{host}[/green] → [yellow]{ip}[/yellow]")
    console.print(f"[white]Scanning [bold]{len(COMMON_PORTS)}[/bold] common ports...[/white]\n")

    # --- Step 2: Scan all ports concurrently ---
    open_ports = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in COMMON_PORTS.keys()
        }
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    elapsed = round(time.time() - start, 2)
    open_ports.sort()

    # --- Step 3: Display results ---
    console.print(f"[white]Scan completed in [bold]{elapsed}s[/bold][/white]\n")

    if not open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(title="Open Ports", border_style="cyan")
    table.add_column("Port", style="bold white")
    table.add_column("Service", style="green")
    table.add_column("Risk", style="yellow")

    # Risk levels for certain ports
    high_risk = [21, 23, 135, 139, 445, 1433, 3389, 5900]
    medium_risk = [22, 25, 53, 110, 143, 3306, 5432, 6379, 27017]

    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown")
        if port in high_risk:
            risk = "[red]High[/red]"
        elif port in medium_risk:
            risk = "[yellow]Medium[/yellow]"
        else:
            risk = "[green]Low[/green]"
        table.add_row(str(port), service, risk)

    console.print(table)
    console.print(f"\n[bold green]Total open ports found: {len(open_ports)}[/bold green]")

    result = []
    high_risk = [21, 23, 135, 139, 445, 1433, 3389, 5900]
    medium_risk = [22, 25, 53, 110, 143, 3306, 5432, 6379, 27017]
    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown")
        if port in high_risk:
            risk = "HIGH"
        elif port in medium_risk:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        result.append({"port": port, "service": service, "risk": risk})
    return result