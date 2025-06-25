#!/usr/bin/env python3
"""
Simple demo of the new fast terminal interface
"""

import time
import threading
from message_system import MessageHandler, MockMessageRouter
from simple_terminal_ui import SimpleTerminalInterface


def main():
    print("\033[1;36m🍐 Pear Simple Chat Demo\033[0m")
    print("Fast, reliable interface without Rich Live conflicts!\n")

    # Create components
    handler = MessageHandler()
    ui = SimpleTerminalInterface()

    # Add some welcome messages
    handler.add_system_message("Welcome to the new simple Pear Chat!")
    handler.add_system_message("This interface is fast and conflict-free")
    handler.add_message("alice", "Hey! This interface works great! 🎉")
    handler.add_message("bob", "So much faster and more reliable!")

    # Start mock router for demo
    router = MockMessageRouter(handler)
    router.start_mock_simulation()

    try:
        # Start the chat interface
        ui.start_chat_interface(
            session_name="simple_demo", is_host=True, message_handler=handler
        )
    except KeyboardInterrupt:
        pass
    finally:
        router.stop_mock_simulation()
        print("\n\033[32mDemo ended. The simple interface works perfectly! 🍐\033[0m")


if __name__ == "__main__":
    main()
