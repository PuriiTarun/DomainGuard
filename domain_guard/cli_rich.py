"""Optional formatted CLI presentation using the shared scan results."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def show_report(result, console=None):
    """Present scan findings without treating unknown results as passing."""
    console = console or Console()
    console.print(Panel.fit(
        "[bold]DomainGuard[/bold]\nWebsite security diagnostics\n[cyan]"
        + result["domain"] + "[/cyan]",
        border_style="cyan"
    ))

    table = Table(title="Connection and TLS")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")
    https, tls = result["https"], result["tls"]
    table.add_row("HTTPS", "CONNECTED" if https["success"] else "UNKNOWN", https["message"])
    table.add_row("TLS", "VERIFIED" if tls["valid"] else "UNKNOWN", tls["expires"] or tls["message"])
    table.add_row("HTTP redirect", result["redirects"]["status"].upper(), result["redirects"]["message"])
    console.print(table)

    dns = Table(title="DNS records")
    dns.add_column("Type")
    dns.add_column("Status")
    dns.add_column("Values")
    for kind, record in result["dns"]["records"].items():
        dns.add_row(kind, record["status"].upper(), ", ".join(record["values"]) or "Not available")
    console.print(dns)

    email = Table(title="Email authentication (presence only)")
    email.add_column("Record")
    email.add_column("Status")
    for kind in ("spf", "dmarc"):
        email.add_row(kind.upper(), result["dns"][kind]["status"].upper())
    console.print(email)

    headers = Table(title="HTTP security headers")
    headers.add_column("Header")
    headers.add_column("Status")
    if result["headers"]["status"] == "checked":
        for name, check in result["headers"]["checks"].items():
            headers.add_row(name, check["status"].upper())
    else:
        headers.add_row("Not checked", "UNKNOWN")
    console.print(headers)
    console.print("[dim]Configuration observations are not proof of a secure website.[/dim]")
