"""
Simple Terminal UI - Dead simple chat interface
Uses only standard terminal operations and ANSI codes
"""

import os
import threading
import time
from typing import Optional, List
from datetime import datetime

from message_system import MessageHandler, ChatMessage


class SimpleTerminalInterface:
    """Dead simple terminal interface for chat"""
    
    def __init__(self, username: str):
        self.running = False
        self.current_user = username
        self.session_name = None
        self.is_host = False
        self.message_handler = None
        self.last_message_count = 0
        
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
        
        # Initial display
        self._render_initial_display()
        
        # Start display updater thread
        display_thread = threading.Thread(target=self._display_loop, daemon=True)
        display_thread.start()
        
        # Start input loop
        self._input_loop()
    
    def _get_username(self) -> str:
        """Get username from user"""
        if self.current_user is None:
            print("\033[1;36mEnter your username: \033[0m", end="", flush=True)
            username = input().strip()
            return username or "user"
        else:
            return self.current_user
    
    def _clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def _render_initial_display(self):
        """Render the initial display setup"""
        self._clear_screen()
        
        # Header
        print(f"\033[1;36m🍐 Pear Chat - {self.session_name}\033[0m")
        print(f"\033[36m{'Host' if self.is_host else 'Participant'} | User: {self.current_user}\033[0m")
        print("\033[36m" + "=" * 50 + "\033[0m")
        print()
        
        # Reserve space for messages (we'll update this area)
        print("\n" * 15)  # Reserve 15 lines for messages
        
        # Fixed bottom section
        print("\033[90m" + "-" * 50 + "\033[0m")
        print("\033[90mType /help for commands | /quit to exit\033[0m")
        print()
        
        # Update message count
        self.last_message_count = len(self.message_handler.get_messages())
        
        # Move cursor up to message area and display messages
        self._update_message_area()
    
    def _display_loop(self):
        """Background thread to update display only when needed"""
        while self.running:
            try:
                # Only update if there are new messages
                current_message_count = len(self.message_handler.get_messages())
                if current_message_count != self.last_message_count:
                    self._update_message_area()
                    self.last_message_count = current_message_count
                time.sleep(1)  # Check for updates every second
            except Exception:
                continue
    
    def _update_message_area(self):
        """Update only the message area without affecting input"""
        # Save current cursor position
        print("\033[s", end="")  # Save cursor position
        
        # Move to message area (line 5, after header)
        print("\033[5;1H", end="")  # Move to line 5, column 1
        
        # Clear the message area (15 lines)
        for _ in range(15):
            print("\033[2K")  # Clear current line
        
        # Move back to start of message area
        print("\033[5;1H", end="")
        
        # Display messages
        messages = self.message_handler.get_messages()
        if messages:
            # Show last 13 messages (leave space for "no messages" line)
            for msg in messages[-13:]:
                timestamp = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M:%S")
                if msg.message_type == "system":
                    print(f"\033[33m[{timestamp}] * {msg.content}\033[0m")
                else:
                    if msg.username == self.current_user:
                        # Your messages in green
                        print(f"\033[90m[{timestamp}]\033[0m \033[1;32m{msg.username}:\033[0m {msg.content}")
                    else:
                        # Other users in blue
                        print(f"\033[90m[{timestamp}]\033[0m \033[1;34m{msg.username}:\033[0m {msg.content}")
        else:
            print("\033[90mNo messages yet... Start chatting!\033[0m")
        
        # Restore cursor position
        print("\033[u", end="", flush=True)  # Restore cursor position
    
    def _input_loop(self):
        """Main input loop with persistent input prompt"""        
        while self.running:
            try:
                # Display persistent input prompt
                print("\033[1;37m> \033[0m", end="", flush=True)
                user_input = input().strip()
                
                # Clear the input line after hitting enter
                print("\033[1A\033[2K", end="")  # Move up one line and clear it
                
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
            self._render_initial_display()
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
        
        print()
        print("\033[1;36m🍐 Available Chat Sessions\033[0m")
        print("\033[36m" + "=" * 30 + "\033[0m")
        
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
        print()
        print("\033[1;36m🍐 Pear Chat\033[0m")
        print("\033[36mP2P Terminal Messaging\033[0m")
        print("\033[36m" + "=" * 25 + "\033[0m")
        print() 