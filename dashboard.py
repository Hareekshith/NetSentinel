from rich.console import Console

console = Console()

def show_banner():
    console.print("[bold cyan]NetSentinel - Network Intrusion Detection System[/bold cyan]\n")

def show_packet(src, port):
    console.print(f"[green]Packet:[/green] {src} → Port {port}")

def alert(message):
    console.print(f"[bold red]ALERT:[/bold red] {message}")
