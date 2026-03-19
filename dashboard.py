from rich.console import Console
from rich.table import Table

console = Console()
def alert(message):
    console.print(f"[bold red]ALERT:[/bold red] {message}")

def show_packet(src, port):
    console.print(f"[green]Packet:[/green] {src} → Port {port}")

def banner():
    console.print("\n[bold cyan]NetSentinel IDS[/bold cyan]\n")

def show_traffic_summary(traffic_counter):

    table = Table(title="Top Talkers")

    table.add_column("IP Address", style="cyan")
    table.add_column("Packets", style="magenta")

    sorted_ips = sorted(
        traffic_counter.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    for ip, count in sorted_ips:
        table.add_row(ip, str(count))

    console.print(table)

def show_results(results):

    if not results:
        console.print("[green]No anomalies detected[/green]")

    for r in results:
        console.print(f"[bold red]ALERT:[/bold red] {r}")
