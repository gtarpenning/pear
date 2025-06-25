#!/usr/bin/env python3
"""
Pear - P2P Terminal Chat
Main CLI entry point
"""

import argparse
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from network_layer import NetworkManager
from message_system import MessageHandler
from simple_terminal_ui import SimpleTerminalInterface
from config import PearConfig


class PearCLI:
    def __init__(self, username: Optional[str] = None):
        self.config = PearConfig()
        self.console = Console()
        self.username = username or self.config.get_username()
        self.network_manager = NetworkManager()
        self.message_handler = MessageHandler()
        self.terminal_ui = SimpleTerminalInterface(self.username)

    def start_session(self, session_name: Optional[str] = None):
        """Start hosting a chat session"""
        if not session_name:
            session_name = f"session_{self.network_manager.get_local_hostname()}"

        print(f"Starting chat session: {session_name}")

        # Create the session first
        self.network_manager.create_session(session_name)

        # Initialize network components
        self.network_manager.start_discovery_service()
        self.network_manager.start_message_server()

        # Start the chat interface
        self.terminal_ui.start_chat_interface(
            session_name=session_name,
            is_host=True,
            message_handler=self.message_handler,
            network_manager=self.network_manager,
        )

    def join_session(self, session_name: Optional[str] = None):
        """Join an existing chat session"""
        if not session_name:
            # Show available sessions and let user choose
            sessions = self.list_sessions(show_output=False)
            if not sessions:
                print("No active sessions found on the network")
                return

            print("Available sessions:")
            for i, session in enumerate(sessions, 1):
                print(f"  {i}. {session['name']} (host: {session['host']})")

            try:
                choice = int(input("Select session number: ")) - 1
                if 0 <= choice < len(sessions):
                    session_name = sessions[choice]["name"]
                else:
                    print("Invalid selection")
                    return
            except (ValueError, KeyboardInterrupt):
                print("\nCancelled")
                return

        print(f"Joining chat session: {session_name}")

        # Connect to the session
        success = self.network_manager.connect_to_session(session_name)
        if not success:
            print(f"Failed to connect to session: {session_name}")
            return

        # Start the chat interface
        self.terminal_ui.start_chat_interface(
            session_name=session_name,
            is_host=False,
            message_handler=self.message_handler,
            network_manager=self.network_manager,
        )

    def list_sessions(self, show_output: bool = True):
        """List available sessions on the network"""
        sessions = self.network_manager.discover_sessions()

        if not sessions:
            if show_output:
                self.console.print(
                    "[yellow]No active sessions found on the network[/yellow]"
                )
            return sessions

        if show_output:
            self._handle_session_display(sessions)

        return sessions

    def _handle_session_display(self, sessions):
        """Handle displaying and interacting with discovered sessions"""
        if len(sessions) == 1:
            self._handle_single_session(sessions[0])
        else:
            self._handle_multiple_sessions(sessions)

    def _handle_single_session(self, session):
        """Handle case when only one session is found"""
        self.console.print(
            f"[green]Found one session: {session['name']} (host: {session['host']}, users: {session['user_count']})[/green]"
        )
        self.console.print("[cyan]Auto-joining...[/cyan]")
        self.join_session(session["name"])

    def _handle_multiple_sessions(self, sessions):
        """Handle case when multiple sessions are found"""
        self._display_session_list(sessions)

        if self._user_wants_to_join():
            self._handle_session_selection(sessions)
        else:
            self.console.print("[cyan]Exiting...[/cyan]")
            sys.exit(0)

    def _display_session_list(self, sessions):
        """Display numbered list of available sessions"""
        self.console.print("[cyan]Available sessions:[/cyan]")
        for i, session in enumerate(sessions, 1):
            self.console.print(
                f"  {i}. {session['name']} (host: {session['host']}, users: {session['user_count']})"
            )

    def _user_wants_to_join(self):
        """Ask user if they want to join a session"""
        self.console.print("\nWould you like to join? (y/n)")
        return input().strip().lower() == "y"

    def _handle_session_selection(self, sessions):
        """Handle user selection of session to join"""
        try:
            session_choice = int(input("Select session number: ")) - 1
            if 0 <= session_choice < len(sessions):
                selected_session = sessions[session_choice]["name"]
                self.join_session(selected_session)
            else:
                self.console.print("[red]Invalid selection[/red]")
        except (ValueError, KeyboardInterrupt):
            self.console.print("\n[yellow]Cancelled[/yellow]")

    def login(self, username: Optional[str] = None):
        """Store username in config for future use"""
        if not username:
            username = self.console.input(
                "[bold cyan]Enter your username: [/bold cyan]"
            ).strip()
            if not username:
                self.console.print("[red]Username cannot be empty[/red]")
                return

        self.config.set_username(username)
        self.console.print(
            Panel(
                f"[green]✅ Username '[bold]{username}[/bold]' saved successfully![/green]\n"
                f"You can now use Pear without entering your username each time.",
                title="Login Complete",
                border_style="green",
            )
        )

    def show_config(self):
        """Show current configuration"""
        config = self.config.get_all()
        if not config:
            self.console.print("[yellow]No configuration found[/yellow]")
            return

        config_text = ""
        for key, value in config.items():
            config_text += f"[cyan]{key}[/cyan]: [white]{value}[/white]\n"

        self.console.print(
            Panel(
                config_text.strip(), title="Current Configuration", border_style="blue"
            )
        )


def main():
    parser = argparse.ArgumentParser(
        description="Pear - P2P Terminal Chat", prog="pear"
    )

    # Global username flag
    parser.add_argument(
        "-u", "--username", help="Username to use (overrides saved config)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Start command
    start_parser = subparsers.add_parser("start", help="Start hosting a chat session")
    start_parser.add_argument(
        "session_name", nargs="?", help="Name of the session to create"
    )

    # Join command
    join_parser = subparsers.add_parser("join", help="Join an existing chat session")
    join_parser.add_argument(
        "session_name", nargs="?", help="Name of the session to join"
    )

    # List command
    list_parser = subparsers.add_parser(
        "list", help="List available sessions on network"
    )

    # Login command
    login_parser = subparsers.add_parser("login", help="Save username to config")
    login_parser.add_argument("username", nargs="?", help="Username to save")

    # Config command
    config_parser = subparsers.add_parser("config", help="Show current configuration")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    pear = PearCLI(username=args.username)

    try:
        if args.command == "start":
            pear.start_session(args.session_name)
        elif args.command == "join":
            pear.join_session(args.session_name)
        elif args.command == "list":
            pear.list_sessions()
        elif args.command == "login":
            pear.login(args.username)
        elif args.command == "config":
            pear.show_config()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
