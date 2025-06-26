#!/usr/bin/env python3
"""
Test script for enhanced network layer
Demonstrates improved error handling and diagnostics
"""

import time
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Import the enhanced network layer
from pear.enhanced_network_layer import EnhancedNetworkManager, NetworkConfig

console = Console()


def test_enhanced_networking():
    """Test the enhanced networking features"""
    console.print(Panel.fit("🔍 Testing Enhanced Network Layer", style="bold cyan"))

    # Create enhanced network manager
    manager = EnhancedNetworkManager()

    # Display initial diagnostics
    console.print("\n[bold yellow]📊 Initial Network Diagnostics[/bold yellow]")
    diagnostics = manager.get_diagnostics()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Local IP", diagnostics["local_ip"])
    table.add_row("Hostname", diagnostics["local_hostname"])
    table.add_row("Corporate Mode", str(diagnostics["config"]["corporate_mode"]))
    table.add_row("Discovery Ports", str(diagnostics["config"]["discovery_ports"]))
    table.add_row("Message Ports", str(diagnostics["config"]["message_ports"]))

    console.print(table)

    # Test session creation
    console.print("\n[bold yellow]🎯 Testing Session Creation[/bold yellow]")
    session_created = manager.create_session("test_session")

    if session_created:
        console.print("[green]✓ Session created successfully![/green]")

        # Test discovery
        console.print("\n[bold yellow]🔍 Testing Enhanced Discovery[/bold yellow]")
        sessions = manager.discover_sessions_enhanced()

        if sessions:
            console.print(f"[green]✓ Found {len(sessions)} session(s):[/green]")
            for session in sessions:
                console.print(
                    f"  - {session.name} on {session.host_ip}:{session.port} (via {session.discovery_method})"
                )
        else:
            console.print("[yellow]○ No sessions discovered[/yellow]")

        # Display connection attempts
        console.print("\n[bold yellow]📈 Connection Attempts Summary[/bold yellow]")
        final_diagnostics = manager.get_diagnostics()

        if final_diagnostics["connection_attempts"]:
            attempts_table = Table(show_header=True, header_style="bold magenta")
            attempts_table.add_column("Protocol", style="cyan")
            attempts_table.add_column("Target", style="yellow")
            attempts_table.add_column("Port", style="blue")
            attempts_table.add_column("Status", style="white")
            attempts_table.add_column("Error", style="red")

            for attempt in final_diagnostics["connection_attempts"]:
                status = (
                    "[green]✓ Success[/green]"
                    if attempt["success"]
                    else "[red]✗ Failed[/red]"
                )
                error = attempt["error"] or "None"
                attempts_table.add_row(
                    attempt["protocol"],
                    attempt["target"],
                    str(attempt["port"]),
                    status,
                    error[:50] + "..." if len(error) > 50 else error,
                )

            console.print(attempts_table)
        else:
            console.print("[dim]No connection attempts recorded[/dim]")

        # Keep session running for a bit
        console.print("\n[dim]Session running for 5 seconds...[/dim]")
        time.sleep(5)

        # Stop the session
        manager.stop()
        console.print("[green]✓ Session stopped cleanly[/green]")

    else:
        console.print("[red]✗ Session creation failed![/red]")

        # Show error details
        final_diagnostics = manager.get_diagnostics()
        if final_diagnostics["last_error"]:
            console.print(f"[red]Last error: {final_diagnostics['last_error']}[/red]")

        # Show failed connection attempts
        failed_attempts = [
            a for a in final_diagnostics["connection_attempts"] if not a["success"]
        ]
        if failed_attempts:
            console.print(
                f"\n[yellow]Failed connection attempts ({len(failed_attempts)}):[/yellow]"
            )
            for attempt in failed_attempts:
                console.print(
                    f"  - {attempt['protocol']} to {attempt['target']}:{attempt['port']}: {attempt['error']}"
                )

        console.print("\n[bold yellow]💡 Recommendations:[/bold yellow]")
        console.print("  1. Run the network debugger: python pear/network_debugger.py")
        console.print("  2. Check if your firewall is blocking the required ports")
        console.print("  3. Try running with different ports using NetworkConfig")
        console.print(
            "  4. If on a corporate network, consider using alternative protocols"
        )

    console.print(f"\n[bold green]🎉 Enhanced Network Test Complete![/bold green]")


def test_custom_config():
    """Test with custom network configuration"""
    console.print(
        Panel.fit("⚙️  Testing Custom Network Configuration", style="bold blue")
    )

    # Create custom config for testing
    custom_config = NetworkConfig(
        discovery_ports=[9999, 9998, 9997],
        message_ports=[9000, 9001, 9002],
        corporate_mode=True,
        timeout_seconds=5,
        retry_attempts=2,
    )

    console.print("[cyan]Using custom configuration:[/cyan]")
    console.print(f"  Discovery ports: {custom_config.discovery_ports}")
    console.print(f"  Message ports: {custom_config.message_ports}")
    console.print(f"  Corporate mode: {custom_config.corporate_mode}")

    # Test with custom config
    manager = EnhancedNetworkManager(config=custom_config)

    console.print("\n[yellow]Testing session creation with custom config...[/yellow]")
    session_created = manager.create_session("custom_test_session")

    if session_created:
        console.print("[green]✓ Custom configuration works![/green]")
        time.sleep(2)
        manager.stop()
    else:
        console.print("[red]✗ Custom configuration failed[/red]")
        diagnostics = manager.get_diagnostics()
        console.print(f"Error: {diagnostics['last_error']}")


def main():
    """Main test function"""
    console.print(
        "[bold cyan]🍐 Pear Chat - Enhanced Network Layer Testing[/bold cyan]\n"
    )

    try:
        # Test 1: Basic enhanced networking
        test_enhanced_networking()

        console.print("\n" + "=" * 60 + "\n")

        # Test 2: Custom configuration
        test_custom_config()

    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed with error: {str(e)}[/red]")
        import traceback

        console.print(f"[dim]{traceback.format_exc()}[/dim]")


if __name__ == "__main__":
    main()
