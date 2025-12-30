#!/usr/bin/env python3
"""
WirelessGuard Pro - Main CLI Application
Professional command-line interface for WiFi security assessment
"""

import sys
import time
from pathlib import Path
from typing import Optional, List
from datetime import datetime

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
except ImportError:
    print("ERROR: Required packages not installed!")
    print("Run: pip install typer rich")
    sys.exit(1)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.interface_manager import InterfaceManager
from src.core.packet_handler import PacketHandler
from src.core.channel_hopper import ChannelHopper
from src.scanner.ap_scanner_v2 import APScannerV2  # FIXED: Use V2 scanner

# Initialize Typer app
app = typer.Typer(
    name="wirelessguard",
    help="🛡️  WirelessGuard Pro - Advanced WiFi Security Assessment Toolkit",
    add_completion=False
)

console = Console()


def banner():
    """Display professional banner"""
    banner_text = """
╦ ╦┬┬─┐┌─┐┬  ┌─┐┌─┐┌─┐╔═╗┬ ┬┌─┐┬─┐┌┬┐  ╔═╗┬─┐┌─┐
║║║│├┬┘├┤ │  ├┤ └─┐└─┐║ ╦│ │├─┤├┬┘ ││  ╠═╝├┬┘│ │
╚╩╝┴┴└─└─┘┴─┘└─┘└─┘└─┘╚═╝└─┘┴ ┴┴└──┴┘  ╩  ┴└─└─┘
    """
    console.print(banner_text, style="bold cyan")
    console.print("Enterprise Wireless Security Assessment Toolkit", style="dim", justify="center")
    console.print("Version 1.0.0 \n", style="dim", justify="center")


@app.command()
def scan(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Wireless interface"),
    duration: int = typer.Option(90, "--duration", "-d", help="Scan duration in seconds"),
    channels: Optional[List[int]] = typer.Option(None, "--channel", "-c", help="Specific channels"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """
    🔍 Scan for WiFi networks
    
    Examples:
        wirelessguard scan                    # 90-second scan
        wirelessguard scan -d 30              # Quick 30-second scan  
        wirelessguard scan -c 1 -c 6 -c 11   # Specific channels
        wirelessguard scan -i wlan1 -v       # Verbose on wlan1
    """
    
    banner()
    
    console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]       🛡️  WirelessGuard Pro - Network Scanner            [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]\n")
    
    # Determine interface
    if not interface:
        interfaces = InterfaceManager.list_interfaces()
        if not interfaces:
            console.print("[bold red]❌ No wireless interfaces found![/bold red]")
            raise typer.Exit(1)
        interface = interfaces[0]
    
    console.print(f"📡 Interface: [cyan]{interface}[/cyan]")
    console.print(f"⏱️  Duration: [cyan]{duration}s[/cyan]")
    
    if channels:
        console.print(f"📶 Channels: [cyan]{channels}[/cyan]")
    else:
        console.print(f"📶 Channels: [cyan]All supported (2.4GHz + 5GHz)[/cyan]")
    
    # Check prerequisites
    import os
    if os.geteuid() != 0:
        console.print("\n[bold red]❌ Root privileges required[/bold red]")
        console.print("[yellow]Run with:[/yellow] sudo python3 -m src.cli.main scan")
        raise typer.Exit(1)
    
    # Enable monitor mode
    console.print("\n🔧 Configuring wireless interface...")
    manager = InterfaceManager(interface)
    
    if not manager.enable_monitor_mode():
        console.print("[bold red]❌ Failed to enable monitor mode[/bold red]")
        raise typer.Exit(1)
    
    console.print("[green]✓ Monitor mode enabled[/green]")
    
    try:
        # Create scanner components (using V2)
        scanner = APScannerV2()
        packet_handler = PacketHandler(interface)
        packet_handler.register_callback(scanner.process_packet)
        
        channel_hopper = ChannelHopper(interface, hop_interval=1.0)
        
        # Register channel callback
        def on_channel_change(channel: int):
            scanner.set_current_channel(channel)
        
        channel_hopper.register_callback(on_channel_change)
        channel_hopper.start()
        
        # Start capture in background thread
        import threading
        capture_thread = threading.Thread(
            target=lambda: packet_handler.start_capture(timeout=duration),
            daemon=True
        )
        capture_thread.start()
        
        console.print("\n[bold green]🚀 Starting scan...[/bold green]\n")
        
        # Progress display with Rich
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Scanning networks...", total=duration)
            
            for i in range(duration):
                time.sleep(1)
                progress.update(task, advance=1)
                
                # Update stats in description
                stats = scanner.get_statistics()
                desc = (f"[cyan]APs: {stats['total_aps']} "
                       f"(2.4GHz: {stats['aps_24ghz']} | 5GHz: {stats['aps_5ghz']}) | "
                       f"Clients: {stats['total_clients']} | "
                       f"Vulnerable: {stats['vulnerable_aps']}")
                progress.update(task, description=desc)
        
        # Cleanup
        channel_hopper.stop()
        packet_handler.stop_capture()
        capture_thread.join(timeout=5)
        
        console.print("\n[green]✓ Scan complete[/green]\n")
        
        # Display results
        _display_results(scanner)
        
        # Export results
        _export_results(scanner, output)
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Scan interrupted by user[/yellow]")
    finally:
        # Restore managed mode
        console.print("\n🔧 Restoring interface...")
        manager.disable_monitor_mode()
        console.print("[green]✓ Interface restored[/green]")
    
    console.print("\n[bold green]✅ Scan complete![/bold green]\n")


def _display_results(scanner: APScannerV2):
    """Display scan results with full BSSID visibility"""
    console.print("\n[bold]📊 Scan Results[/bold]\n")
    
    stats = scanner.get_statistics()
    
    # Statistics panel
    stats_text = f"""
[cyan]Total Networks:[/cyan] {stats['total_aps']}
[cyan]2.4GHz:[/cyan] {stats['aps_24ghz']} | [cyan]5GHz:[/cyan] {stats['aps_5ghz']}
[cyan]Clients:[/cyan] {stats['total_clients']} ({stats['connected_clients']} connected)

[yellow]Security Analysis:[/yellow]
  • Open: {stats['open_aps']}
  • WPS Enabled: {stats['wps_aps']}
  • Vulnerable: {stats['vulnerable_aps']}
  • Hidden: {stats['hidden_aps']}
  • Vendor ID Rate: {stats['vendor_identification_rate']:.1f}%
    """
    
    console.print(Panel(stats_text, title="Statistics", border_style="green"))
    
    # AP table - OPTION 1: Compact table with full BSSID
    if stats['total_aps'] > 0:
        console.print("\n[bold]Top Access Points:[/bold]\n")
        
        # Use expand=False and no_wrap to prevent truncation
        table = Table(show_header=True, header_style="bold cyan", expand=False, box=None)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("SSID", width=16, overflow="ellipsis")
        table.add_column("BSSID", width=17, no_wrap=True)  
        table.add_column("Ch", justify="center", width=3, no_wrap=True)
        table.add_column("Band", width=5, no_wrap=True)
        table.add_column("Enc", width=8, overflow="ellipsis")
        table.add_column("RSSI", justify="right", width=5, no_wrap=True)
        table.add_column("Cl", justify="right", width=3, no_wrap=True)
        table.add_column("Vuln", justify="center", width=4, no_wrap=True)
        
        aps = sorted(scanner.get_all_aps(), key=lambda x: x.average_rssi, reverse=True)
        
        for idx, ap in enumerate(aps[:25], 1):  # Show top 25
            # Vulnerability indicator
            if ap.vulnerability_level.value == "Critical":
                vuln = "[bold red]CRIT[/bold red]"
            elif ap.vulnerability_level.value == "High":
                vuln = "[red]HIGH[/red]"
            elif ap.vulnerability_level.value == "Medium":
                vuln = "[yellow]MED[/yellow]"
            elif ap.vulnerability_level.value == "Low":
                vuln = "[green]LOW[/green]"
            else:
                vuln = "-"
            
            table.add_row(
                str(idx),
                (ap.ssid or "(Hidden)")[:15],
                ap.bssid,  # Full BSSID
                str(ap.channel),
                ap.band[:5],
                ap.encryption[:7],
                str(ap.average_rssi),
                str(ap.client_count),
                vuln
            )
        
        console.print(table)
        
        if len(aps) > 25:
            console.print(f"\n[dim]... and {len(aps) - 25} more networks[/dim]")
        
        # Add helper text
        console.print("\n[dim]💡 Complete details with full BSSIDs saved to JSON/CSV files[/dim]")


def _export_results(scanner: APScannerV2, output_path: Optional[str]):
    """Export scan results to files"""
    console.print("\n[bold]📁 Exporting Results[/bold]\n")
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = "data/reports"
    
    # Create directory
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    
    # Export to JSON
    json_file = output_path or f"{reports_dir}/scan_{timestamp}.json"
    scanner.export_to_json(json_file)
    console.print(f"[green]✓ JSON:[/green] {json_file}")
    
    # Export to CSV
    csv_file = f"{reports_dir}/scan_{timestamp}.csv"
    scanner.export_to_csv(csv_file)
    console.print(f"[green]✓ CSV:[/green] {csv_file}")


@app.command()
def interfaces():
    """
    📡 List available wireless interfaces
    
    Shows all wireless network adapters detected on the system.
    """
    banner()
    
    console.print("\n[bold cyan]Available Wireless Interfaces[/bold cyan]\n")
    
    ifaces = InterfaceManager.list_interfaces()
    
    if not ifaces:
        console.print("[yellow]No wireless interfaces found[/yellow]")
        return
    
    for iface in ifaces:
        manager = InterfaceManager(iface)
        info = manager.get_info()
        
        console.print(f"[bold]{info.name}[/bold]")
        console.print(f"  MAC: {info.mac}")
        console.print(f"  Driver: {info.driver}")
        console.print(f"  Mode: {info.mode}")
        if info.channel:
            console.print(f"  Channel: {info.channel}")
        console.print()


@app.command()
def version():
    """
    📦 Show version information
    """
    version_info = """
[bold cyan]🛡️  WirelessGuard Pro[/bold cyan]

[cyan]Version:[/cyan] 1.0.0
[cyan]Module:[/cyan] 5 - Professional CLI Interface
[cyan]License:[/cyan] Educational Use Only

[dim]A professional wireless security assessment toolkit
for penetration testing and network analysis.[/dim]
    """
    
    console.print(Panel(version_info, border_style="cyan", title="Version Info"))


@app.callback()
def main():
    """
    🛡️  WirelessGuard Pro - Advanced WiFi Security Assessment Toolkit
    
    A comprehensive wireless security testing framework with intelligent
    network discovery, vulnerability assessment, and professional reporting.
    """
    pass


if __name__ == "__main__":
    app()
