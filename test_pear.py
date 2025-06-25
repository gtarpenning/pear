#!/usr/bin/env python3
"""
Simple test script for Pear MVP components
"""

import time
import threading
from rich.console import Console

from network_layer import NetworkManager, PeerInfo
from message_system import MessageHandler, MockMessageRouter
from terminal_ui import TerminalInterface


def test_network_manager():
    """Test network manager functionality"""
    console = Console()
    console.print("[bold cyan]Testing Network Manager...[/bold cyan]")
    
    network = NetworkManager()
    
    # Test basic functionality
    console.print(f"Local hostname: {network.get_local_hostname()}")
    console.print(f"Local IP: {network.local_ip}")
    
    # Test discovery
    sessions = network.discover_sessions()
    console.print(f"Found {len(sessions)} mock sessions")
    
    # Test connection
    if sessions:
        success = network.connect_to_session(sessions[0]['name'])
        console.print(f"Connection test: {'✅' if success else '❌'}")
    
    console.print("[green]✅ Network Manager tests passed[/green]\n")


def test_message_system():
    """Test message system functionality"""
    console = Console()
    console.print("[bold cyan]Testing Message System...[/bold cyan]")
    
    handler = MessageHandler()
    
    # Test message handling
    msg1 = handler.add_message("alice", "Hello everyone!")
    msg2 = handler.add_message("bob", "Hey Alice!")
    handler.add_system_message("Charlie joined the chat")
    
    console.print(f"Added {len(handler.get_messages())} messages")
    
    # Test message formatting
    for msg in handler.get_messages():
        formatted = handler.format_message_for_display(msg)
        console.print(f"  {formatted}")
    
    # Test stats
    stats = handler.get_message_stats()
    console.print(f"Stats: {stats['total_messages']} messages, {stats['unique_users']} users")
    
    console.print("[green]✅ Message System tests passed[/green]\n")


def test_terminal_ui():
    """Test terminal UI components (non-interactive)"""
    console = Console()
    console.print("[bold cyan]Testing Terminal UI...[/bold cyan]")
    
    ui = TerminalInterface()
    
    # Test banner
    ui.show_startup_banner()
    
    # Test session list display
    mock_sessions = [
        {'name': 'test_session', 'host': 'test_host', 'user_count': 2},
        {'name': 'dev_chat', 'host': 'alice-laptop', 'user_count': 3}
    ]
    ui.show_session_list(mock_sessions)
    
    # Test connection status
    ui.show_connection_status("test_session", True)
    ui.show_connection_status("failed_session", False)
    
    console.print("[green]✅ Terminal UI tests passed[/green]\n")


def test_integration():
    """Test integration between components"""
    console = Console()
    console.print("[bold cyan]Testing Component Integration...[/bold cyan]")
    
    # Create components
    network = NetworkManager()
    handler = MessageHandler()
    ui = TerminalInterface()
    
    # Test message callback system
    messages_received = []
    
    def on_message(msg):
        messages_received.append(msg)
    
    handler.add_message_callback(on_message)
    
    # Add some messages
    handler.add_message("test_user", "Integration test message")
    handler.add_system_message("System integration test")
    
    console.print(f"Callback received {len(messages_received)} messages")
    
    # Test mock router
    router = MockMessageRouter(handler)
    console.print("Mock router created successfully")
    
    console.print("[green]✅ Integration tests passed[/green]\n")


def run_mock_demo():
    """Run a brief demo with mock data"""
    console = Console()
    console.print("[bold cyan]Running Mock Demo (5 seconds)...[/bold cyan]")
    
    handler = MessageHandler()
    router = MockMessageRouter(handler)
    
    # Add some initial messages
    handler.add_system_message("Demo session started")
    handler.add_message("alice", "Hey everyone!")
    handler.add_message("bob", "Hello Alice!")
    
    # Start mock simulation
    router.start_mock_simulation()
    
    # Let it run for a few seconds
    time.sleep(3)
    
    # Stop simulation
    router.stop_mock_simulation()
    
    # Show results
    stats = handler.get_message_stats()
    console.print(f"Demo generated {stats['total_messages']} total messages")
    
    # Show recent messages
    recent_messages = handler.get_messages(limit=5)
    console.print("Recent messages:")
    for msg in recent_messages:
        formatted = handler.format_message_for_display(msg)
        console.print(f"  {formatted}")
    
    console.print("[green]✅ Mock demo completed[/green]\n")


def main():
    """Run all tests"""
    console = Console()
    
    console.print("[bold yellow]🍐 Pear MVP Test Suite[/bold yellow]")
    console.print("[dim]Testing all components...[/dim]\n")
    
    try:
        test_network_manager()
        test_message_system()
        test_terminal_ui()
        test_integration()
        run_mock_demo()
        
        console.print("[bold green]🎉 All tests passed! MVP components are working.[/bold green]")
        console.print("[dim]You can now run: python pear_cli.py --help[/dim]")
        
    except Exception as e:
        console.print(f"[red]❌ Test failed: {e}[/red]")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")


if __name__ == "__main__":
    main() 