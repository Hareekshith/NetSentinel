from rich.console import Console

console = Console()

def alert(message):
    console.print(f"[bold red]ALERT:[/bold red] {message}")

def show_packet(src, port):
    console.print(f"[green]Packet:[/green] {src} → Port {port}")

def banner():
    console.print("\n[bold cyan]NetSentinel IDS[/bold cyan]\n")

def show_results(results):
    if not results:
        console.print("[green]No anomalies detected[/green]")
    for r in results:
        console.print(f"[bold red]ALERT:[/bold red] {r}")
