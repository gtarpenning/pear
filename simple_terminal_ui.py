"""
Simple Terminal UI - Fast and reliable chat interface
Uses basic terminal control instead of Rich Live display
"""

import os
import threading
import time
from typing import Optional, List
from datetime import datetime

from rich.console import Console
from rich.text import Text
from rich import box
from rich.panel import Panel
from rich.table import Table

from message_system import MessageHandler, ChatMessage


class SimpleTerminalInterface:
    """Simple, fast terminal interface for chat"""
    
    def __init__(self):
        self.console = Console()
        self.running = False
        self.current_user = None
        self.session_name = None
        self.is_host = False
        self.message_handler = None
        self.last_display_height = 0
        self.input_active = False  # Flag to pause display updates during input
        
    def start_chat_interface(self, session_name: str, is_host: bool, message_handler: MessageHandler):
        """Start the main chat interface"""
        self.session_name = session_name
        self.is_host = is_host
        self.message_handler = message_handler
        self.current_user = self._get_username()
        self.running = True
        
        # Add welcome messages
        if is_host:
            message_handler.add_system_message(f"Started chat session: {session_name}")
            message_handler.add_system_message(f"You are hosting this session")
        else:
            message_handler.add_system_message(f"Joined chat session: {session_name}")
        
        message_handler.add_system_message(f"Welcome {self.current_user}! Type /help for commands")
        
        # Start display updater thread
        display_thread = threading.Thread(target=self._display_loop, daemon=True)
        display_thread.start()
        
        # Start input loop
        self._input_loop()
    
    def _get_username(self) -> str:
        """Get username from user"""
        return self.console.input("[bold cyan]Enter your username: [/bold cyan]") or "user"
    
    def _clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def _move_cursor_up(self, lines: int):
        """Move cursor up by specified lines"""
        print(f"\033[{lines}A", end="")
    
    def _clear_lines(self, lines: int):
        """Clear specified number of lines"""
        for _ in range(lines):
            print("\033[2K\033[1A", end="")  # Clear line and move up
        print("\033[2K", end="")  # Clear current line
    
    def _display_loop(self):
        """Background thread to update display"""
        while self.running:
            try:
                # Only update display if not actively getting input
                if not self.input_active:
                    self._render_chat_display()
                time.sleep(3)  # Update every 3 seconds
            except Exception:
                continue
    
    def _render_chat_display(self):
        """Render the complete chat display"""
        # Clear screen completely
        self._clear_screen()
        
        # Get terminal dimensions
        width = min(80, self.console.size.width)
        
        # Header
        header = f"🍐 Pear Chat - {self.session_name} ({'Host' if self.is_host else 'Participant'})"
        border = "=" * (width - 4)
        
        print(f"\033[1;36m{border}\033[0m")
        print(f"\033[1;36m{header.center(len(border))}\033[0m") 
        print(f"\033[1;36m{border}\033[0m")
        print()
        
        # Messages section
        print("\033[1;32m💬 Messages:\033[0m")
        print("─" * (width - 4))
        
        messages = self.message_handler.get_messages()
        if messages:
            # Show last 10 messages to keep it clean
            for msg in messages[-10:]:
                timestamp = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M:%S")
                if msg.message_type == "system":
                    print(f"\033[33m[{timestamp}] * {msg.content}\033[0m")
                else:
                    user_color = "\033[1;32m" if msg.username == self.current_user else "\033[1;34m"
                    print(f"\033[90m[{timestamp}]\033[0m {user_color}{msg.username}:\033[0m {msg.content}")
        else:
            print("\033[90mNo messages yet... Start chatting!\033[0m")
        
        print()
        
        # Users section
        print("\033[1;34m👥 Users:\033[0m")
        print("─" * 20)
        
        # Mock users for now
        users = [
            (self.current_user, "online", True),
            ("alice", "online", False),
            ("bob", "typing", False)
        ]
        
        for name, status, is_self in users:
            status_icon = "🟢" if status == "online" else "🟡"
            name_display = f"{name} (you)" if is_self else name
            color = "\033[1;36m" if is_self else "\033[37m"
            print(f"{color}{status_icon} {name_display}\033[0m")
        
        print()
        print("─" * (width - 4))
        print("\033[90m/help for commands • /quit to exit\033[0m")
        print()
    
    def _input_loop(self):
        """Main input loop"""
        # Initial display
        self._render_chat_display()
        
        while self.running:
            try:
                # Get user input
                user_input = input("\033[1;36m💬 Message: \033[0m").strip()
                
                if not user_input:
                    continue
                
                if user_input.startswith('/'):
                    self._handle_command(user_input)
                else:
                    # Send regular message
                    self.message_handler.add_message(self.current_user, user_input)
                    
                    # Mock: simulate sending to network
                    if hasattr(self, 'network_manager'):
                        self.network_manager.send_message(user_input, self.current_user)
                
                # Trigger immediate display update
                self._render_chat_display()
                        
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break
            except Exception as e:
                print(f"\033[31mError: {e}\033[0m")
                continue
    
    def _handle_command(self, command: str):
        """Handle chat commands"""
        cmd_parts = command[1:].split()
        cmd = cmd_parts[0].lower()
        
        if cmd == "help":
            self._show_help()
        elif cmd == "quit" or cmd == "exit":
            self.running = False
        elif cmd == "clear":
            self.message_handler.clear_messages()
            self._clear_screen()
        elif cmd == "stats":
            self._show_stats()
        elif cmd == "users":
            self._show_users()
        else:
            self.message_handler.add_system_message(f"Unknown command: {command}")
    
    def _show_help(self):
        """Show help message"""
        help_text = """Available commands:
/help - Show this help message
/quit or /exit - Leave the chat
/clear - Clear message history and screen
/stats - Show chat statistics
/users - Show connected users"""
        
        self.message_handler.add_system_message(help_text)
    
    def _show_stats(self):
        """Show chat statistics"""
        stats = self.message_handler.get_message_stats()
        
        stats_text = f"""Chat Statistics:
• Total messages: {stats['total_messages']}
• Unique users: {stats['unique_users']}
• Session started: {datetime.fromtimestamp(stats['first_message_time']).strftime('%H:%M:%S') if stats['first_message_time'] else 'N/A'}"""
        
        self.message_handler.add_system_message(stats_text)
    
    def _show_users(self):
        """Show connected users"""
        users_text = "Connected users:\n• alice (online)\n• bob (typing)\n• you (online)"
        self.message_handler.add_system_message(users_text)
    
    def show_session_list(self, sessions: List[dict]):
        """Show available sessions"""
        if not sessions:
            print("\033[33mNo active sessions found on the network\033[0m")
            return
        
        print("\n\033[1;36m🍐 Available Chat Sessions\033[0m")
        print("=" * 40)
        
        for i, session in enumerate(sessions, 1):
            print(f"{i}. \033[1;32m{session['name']}\033[0m")
            print(f"   Host: \033[34m{session['host']}\033[0m")
            print(f"   Users: \033[33m{session['user_count']}\033[0m")
            print()
    
    def show_connection_status(self, session_name: str, success: bool):
        """Show connection status"""
        if success:
            print(f"\033[32m✅ Successfully connected to {session_name}\033[0m")
        else:
            print(f"\033[31m❌ Failed to connect to {session_name}\033[0m")
    
    def show_startup_banner(self):
        """Show the startup banner"""
        banner = """
\033[1;36m
╔════════════════════════════════════════╗
║            🍐 Pear Chat                ║
║     P2P Terminal Messaging             ║
╚════════════════════════════════════════╝
\033[0m
Real-time messaging on your local network
"""
        print(banner) 