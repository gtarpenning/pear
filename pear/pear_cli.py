#!/usr/bin/env python3
"""
Pear - P2P Terminal Chat
Simplified CLI entry point using command classes
"""

import argparse
import sys
from typing import Optional

from rich.console import Console

from .network_core import NetworkManager
from .config import PearConfig
from .cli_commands import SessionCommands, ConfigCommands, ChatCommands, HelpCommands


class PearCLI:
    """Simplified main CLI class"""
    
    def __init__(self, username: Optional[str] = None):
        self.console = Console()
        self.config = PearConfig()
        self.network_manager = NetworkManager()
        
        # Set username
        self.username = username or self.config.get_username() or "user"
        
        # Initialize command handlers
        self.session_commands = SessionCommands(self.console, self.network_manager)
        self.config_commands = ConfigCommands(self.console, self.config)
        self.chat_commands = ChatCommands(self.username)
        self.help_commands = HelpCommands(self.console)
    
    def start_session(self, session_name: Optional[str] = None):
        """Start hosting a chat session"""
        success = self.session_commands.start_session(session_name, self.username)
        if success:
            self.chat_commands.start_chat_interface(
                session_name or f"session_{self.network_manager.get_local_hostname()}",
                is_host=True,
                network_manager=self.network_manager
            )
    
    def join_session(self, session_name: Optional[str] = None):
        """Join an existing chat session"""
        joined_session = self.session_commands.join_session(session_name)
        if joined_session:
            self.chat_commands.start_chat_interface(
                session_name=joined_session,
                is_host=False,
                network_manager=self.network_manager
            )
    
    def connect_direct(self, target: str):
        """Connect directly to a host"""
        success = self.session_commands.connect_direct(target)
        if success:
            self.chat_commands.start_chat_interface(
                session_name=f"direct_{target}",
                is_host=False,
                network_manager=self.network_manager
            )
    
    def list_sessions(self):
        """List available sessions"""
        sessions = self.session_commands.list_sessions()
        
        # If sessions found, offer to join one
        if sessions and len(sessions) == 1:
            session_name = self.session_commands._prompt_single_session(sessions[0])
            if session_name:
                self.join_session(session_name)
        elif sessions and len(sessions) > 1:
            session_name = self.session_commands._prompt_multiple_sessions(sessions)
            if session_name:
                self.join_session(session_name)
    
    def login(self, username: Optional[str] = None):
        """Set username"""
        self.username = self.config_commands.set_username(username)
    
    def show_config(self):
        """Show current configuration"""
        self.config_commands.show_config()
    
    def show_help(self):
        """Show help information"""
        self.help_commands.show_help()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="Pear - P2P Terminal Chat for local networks",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Start command
    start_parser = subparsers.add_parser("start", help="Start hosting a session")
    start_parser.add_argument("session_name", nargs="?", help="Session name (optional)")
    
    # Join command
    join_parser = subparsers.add_parser("join", help="Join a session")
    join_parser.add_argument("session_name", nargs="?", help="Session name (optional)")
    
    # Connect command
    connect_parser = subparsers.add_parser("connect", help="Connect directly to a host")
    connect_parser.add_argument("target", help="Target IP address or IP:port")
    
    # List command
    subparsers.add_parser("list", help="List available sessions")
    
    # Login command
    login_parser = subparsers.add_parser("login", help="Set username")
    login_parser.add_argument("username", nargs="?", help="Username (optional)")
    
    # Config command
    subparsers.add_parser("config", help="Show configuration")
    
    # Help command
    subparsers.add_parser("help", help="Show help")
    
    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = PearCLI()
    
    try:
        if args.command == "start":
            cli.start_session(args.session_name)
        elif args.command == "join":
            cli.join_session(args.session_name)
        elif args.command == "connect":
            cli.connect_direct(args.target)
        elif args.command == "list":
            cli.list_sessions()
        elif args.command == "login":
            cli.login(args.username)
        elif args.command == "config":
            cli.show_config()
        elif args.command == "help":
            cli.show_help()
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        cli.console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        cli.console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
