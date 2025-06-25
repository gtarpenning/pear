#!/usr/bin/env python3
"""
Pear - P2P Terminal Chat
Main CLI entry point
"""

import argparse
import sys
from typing import Optional

from network_layer import NetworkManager
from message_system import MessageHandler
from simple_terminal_ui import SimpleTerminalInterface
from config import PearConfig


class PearCLI:
    def __init__(self):
        self.network_manager = NetworkManager()
        self.message_handler = MessageHandler()
        self.terminal_ui = SimpleTerminalInterface()
        self.config = PearConfig()
        
    def _get_username(self, provided_username: Optional[str] = None) -> Optional[str]:
        """Get username from various sources in order of priority"""
        if provided_username:
            return provided_username
        
        config_username = self.config.get_username()
        if config_username:
            return config_username
        
        # Fallback to prompting (this will be handled by terminal UI)
        return None
        
    def start_session(self, session_name: Optional[str] = None, username: Optional[str] = None):
        """Start hosting a chat session"""
        if not session_name:
            session_name = f"session_{self.network_manager.get_local_hostname()}"
        
        print(f"Starting chat session: {session_name}")
        
        # Initialize network components
        self.network_manager.start_discovery_service()
        self.network_manager.start_message_server()
        
        # Get username
        username = self._get_username(username)
        
        # Start the chat interface
        self.terminal_ui.start_chat_interface(
            session_name=session_name,
            is_host=True,
            message_handler=self.message_handler,
            username=username
        )
    
    def join_session(self, session_name: Optional[str] = None, username: Optional[str] = None):
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
                    session_name = sessions[choice]['name']
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
        
        # Get username
        username = self._get_username(username)
        
        # Start the chat interface
        self.terminal_ui.start_chat_interface(
            session_name=session_name,
            is_host=False,
            message_handler=self.message_handler,
            username=username
        )
    
    def list_sessions(self, show_output: bool = True):
        """List available sessions on the network"""
        sessions = self.network_manager.discover_sessions()
        
        if show_output:
            if sessions:
                print("Available sessions:")
                for session in sessions:
                    print(f"  - {session['name']} (host: {session['host']}, users: {session['user_count']})")
            else:
                print("No active sessions found on the network")
        
        return sessions
    
    def login(self, username: str):
        """Store username in config for future sessions"""
        self.config.set_username(username)
        print(f"Username '{username}' saved to config")
    
    def logout(self):
        """Clear stored username from config"""
        self.config.set_username("")
        print("Username cleared from config")
    
    def config_info(self):
        """Show current configuration"""
        settings = self.config.get_all_settings()
        if settings:
            print("Current configuration:")
            for key, value in settings.items():
                print(f"  {key}: {value}")
        else:
            print("No configuration found")


def main():
    parser = argparse.ArgumentParser(
        description="Pear - P2P Terminal Chat",
        prog="pear"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start hosting a chat session')
    start_parser.add_argument('session_name', nargs='?', help='Name of the session to create')
    start_parser.add_argument('-u', '--username', help='Username for the chat session')
    
    # Join command  
    join_parser = subparsers.add_parser('join', help='Join an existing chat session')
    join_parser.add_argument('session_name', nargs='?', help='Name of the session to join')
    join_parser.add_argument('-u', '--username', help='Username for the chat session')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available sessions on network')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Store username in config')
    login_parser.add_argument('username', help='Username to store')
    
    # Logout command
    logout_parser = subparsers.add_parser('logout', help='Clear stored username from config')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Show current configuration')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    pear = PearCLI()
    
    try:
        if args.command == 'start':
            pear.start_session(args.session_name, args.username)
        elif args.command == 'join':
            pear.join_session(args.session_name, args.username)
        elif args.command == 'list':
            pear.list_sessions()
        elif args.command == 'login':
            pear.login(args.username)
        elif args.command == 'logout':
            pear.logout()
        elif args.command == 'config':
            pear.config_info()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 