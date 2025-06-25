#!/usr/bin/env python3
"""
Quick demo of the improved chat interface
"""

import time
import threading
from rich.console import Console

from network_layer import NetworkManager
from message_system import MessageHandler, MockMessageRouter
from terminal_ui import TerminalInterface


def main():
    console = Console()
    console.print("[bold cyan]🍐 Pear Chat Interface Demo[/bold cyan]")
    console.print(
        "[dim]This demo shows the improved UI with visible input area[/dim]\n"
    )

    # Create components
    network = NetworkManager()
    handler = MessageHandler()
    ui = TerminalInterface()

    # Add some welcome messages
    handler.add_system_message("Welcome to Pear Chat Demo!")
    handler.add_system_message("The input area is now properly visible")
    handler.add_message("alice", "Hey everyone! 👋")
    handler.add_message("bob", "Love the new interface!")

    # Start mock router for realistic demo
    router = MockMessageRouter(handler)
    router.start_mock_simulation()

    try:
        # Start the chat interface
        ui.start_chat_interface(
            session_name="demo_session", is_host=True, message_handler=handler
        )
    except KeyboardInterrupt:
        pass
    finally:
        router.stop_mock_simulation()
        console.print("\n[green]Demo ended. Thanks for trying Pear! 🍐[/green]")


if __name__ == "__main__":
    main()
