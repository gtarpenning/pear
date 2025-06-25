"""
Simple Terminal UI - Dead simple chat interface
Uses only standard terminal operations and ANSI codes
"""

import os
import threading
import time
import json
import shutil
from typing import Optional, List
from datetime import datetime

from message_system import MessageHandler, ChatMessage
from llm_agent import LLMAgent


class SimpleTerminalInterface:
    """Dead simple terminal interface for chat"""

    def __init__(self, username: str):
        self.running = False
        self.current_user = username
        self.session_name = None
        self.is_host = False
        self.message_handler = None
        self.last_message_count = 0
        self.network_manager = None
        self.llm_agent = None
        self.terminal_height = 24  # Default fallback
        self.terminal_width = 80  # Default fallback
        self.username_colors = {}  # Dictionary to store username-color assignments
        self.available_colors = [
            "\033[1;31m",  # Red
            "\033[1;32m",  # Green
            "\033[1;33m",  # Yellow
            "\033[1;34m",  # Blue
            "\033[1;35m",  # Magenta
            "\033[1;36m",  # Cyan
            "\033[1;91m",  # Bright Red
            "\033[1;92m",  # Bright Green
            "\033[1;93m",  # Bright Yellow
            "\033[1;94m",  # Bright Blue
            "\033[1;95m",  # Bright Magenta
            "\033[1;96m",  # Bright Cyan
        ]
        self.color_index = 0

    def start_chat_interface(
        self,
        session_name: str,
        is_host: bool,
        message_handler: MessageHandler,
        network_manager=None,
    ):
        """Start the main chat interface"""
        self.session_name = session_name
        self.is_host = is_host
        self.message_handler = message_handler
        self.network_manager = network_manager
        self.current_user = self._get_username()
        self.running = True

        # Initialize LLM agent with network manager (only for host to avoid multiple AI responses)
        self.llm_agent = LLMAgent(
            self.message_handler, self.network_manager if self.is_host else None
        )

        # Set up network callbacks if network manager is provided
        if self.network_manager:
            self.network_manager.add_message_callback(self._handle_network_event)

        # Add welcome messages
        if is_host:
            message_handler.add_system_message(f"Started chat session: {session_name}")
            message_handler.add_system_message(f"You are hosting this session")
        else:
            message_handler.add_system_message(f"Joined chat session: {session_name}")

        message_handler.add_system_message(
            f"Welcome {self.current_user}! Type /help for commands"
        )

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
        os.system("clear" if os.name == "posix" else "cls")

    def _get_terminal_size(self):
        """Get current terminal size"""
        try:
            size = shutil.get_terminal_size()
            self.terminal_height = size.lines
            self.terminal_width = size.columns
        except Exception:
            # Fallback to defaults if unable to get terminal size
            self.terminal_height = 24
            self.terminal_width = 80

    def _render_initial_display(self):
        """Render the initial display setup"""
        self._get_terminal_size()
        self._clear_screen()

        # Header (4 lines)
        print(f"\033[1;36m🍐 Pear Chat - {self.session_name}\033[0m")
        print(
            f"\033[36m{'Host' if self.is_host else 'Participant'} | User: {self.current_user}\033[0m"
        )
        print("\033[36m" + "=" * min(50, self.terminal_width) + "\033[0m")
        print()

        # Calculate available space for messages
        # Header: 4 lines, Footer: 3 lines, Input: 1 line = 8 lines total reserved
        self.message_area_height = max(5, self.terminal_height - 8)

        # Reserve space for messages
        for _ in range(self.message_area_height):
            print()

        # Fixed bottom section - positioned at bottom
        self._render_footer()

        # Update message count
        self.last_message_count = len(self.message_handler.get_messages())

        # Display messages in the reserved area
        self._update_message_area()

        # Position cursor for input at the very bottom
        self._position_input_cursor()

    def _render_footer(self):
        """Render the footer section at the bottom"""
        print(f"\033[90m{'-' * min(50, self.terminal_width)}\033[0m")
        print("\033[90mType /help for commands | /quit to exit\033[0m")
        print()  # Extra line for input

    def _position_input_cursor(self):
        """Position cursor at the input line (bottom of terminal)"""
        print(f"\033[{self.terminal_height};1H", end="")  # Move to last line

    def _display_loop(self):
        """Background thread to update display only when needed"""
        while self.running:
            try:
                # Check for terminal size changes
                old_height = self.terminal_height
                self._get_terminal_size()

                # Only update if there are new messages or terminal was resized
                current_message_count = len(self.message_handler.get_messages())
                if (
                    current_message_count != self.last_message_count
                    or old_height != self.terminal_height
                ):
                    if old_height != self.terminal_height:
                        # Terminal was resized, recalculate layout
                        self.message_area_height = max(5, self.terminal_height - 8)
                        self._render_initial_display()
                    else:
                        # Just update messages
                        self._update_message_area()
                    self.last_message_count = current_message_count
                time.sleep(1)  # Check for updates every second
            except Exception:
                continue

    def _update_message_area(self):
        """Update only the message area without affecting input"""
        # Save current cursor position
        print("\033[s", end="")

        # Move to message area (line 5, after header)
        print("\033[5;1H", end="")

        # Clear the message area using dynamic height
        for _ in range(self.message_area_height):
            print("\033[2K")

        # Move back to start of message area
        print("\033[5;1H", end="")

        # Display messages
        messages = self.message_handler.get_messages()
        if messages:
            # Calculate how many messages we can show (leave 1 line buffer)
            max_messages = max(1, self.message_area_height - 1)

            # Show only the most recent messages that fit
            for msg in messages[-max_messages:]:
                formatted_message = self._format_message(msg)
                print(formatted_message)
        else:
            print("\033[90mNo messages yet... Start chatting!\033[0m")

        # Restore cursor position
        print("\033[u", end="", flush=True)

    def _input_loop(self):
        """Main input loop with input at bottom of terminal"""
        while self.running:
            try:
                # Simple approach: let input() work naturally at current cursor position
                print("\033[1;37m> \033[0m", end="", flush=True)
                user_input = input().strip()

                # After input(), cursor is naturally on next line, just clear the previous line
                print("\033[1A\033[2K", end="", flush=True)  # Move up and clear

                if not user_input:
                    continue

                if user_input.startswith("/"):
                    self._handle_command(user_input)
                else:
                    # Send regular message
                    self.message_handler.add_message(self.current_user, user_input)

                    # Send to network if available
                    if self.network_manager:
                        self.network_manager.send_message(user_input, self.current_user)

            except (EOFError, KeyboardInterrupt):
                self.running = False
                break
            except Exception as e:
                print(f"\033[31mError: {e}\033[0m")
                time.sleep(1)
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
        elif cmd == "llm":
            self._handle_llm_command(cmd_parts[1:] if len(cmd_parts) > 1 else [])
        else:
            self.message_handler.add_system_message(f"Unknown command: {command}")

    def _handle_llm_command(self, args: List[str]):
        """Handle LLM-related commands"""
        if not args:
            self.message_handler.add_system_message(
                "LLM commands: /llm invite [name], /llm leave, /llm model <model_name>"
            )
            return

        subcommand = args[0].lower()

        if self.is_host:
            # Host handles commands directly
            if subcommand == "invite":
                custom_name = args[1] if len(args) > 1 else None
                self._invite_llm(custom_name)
            elif subcommand == "leave":
                self._remove_llm()
            elif subcommand == "model":
                if len(args) > 1:
                    model_name = args[1]
                    self._set_llm_model(model_name)
                else:
                    self.message_handler.add_system_message(
                        "Please specify a model name: /llm model <model_name>"
                    )
            else:
                self.message_handler.add_system_message(
                    f"Unknown LLM command: {subcommand}. Use /llm for help."
                )
        else:
            # Peer sends command to host via network
            self._send_llm_command_to_host(args)

    def _invite_llm(self, custom_name: Optional[str] = None):
        """Invite LLM agent to the chat"""
        if self.llm_agent.is_active():
            current_name = self.llm_agent.get_name()
            self.message_handler.add_system_message(
                f"{current_name} is already active in the chat."
            )
            return

        try:
            agent_name = self.llm_agent.activate(custom_name)
            self.message_handler.add_message(
                "SYSTEM", f"{agent_name} has joined the chat", "user_event"
            )
        except Exception as e:
            self.message_handler.add_system_message(
                f"Failed to activate AI assistant: {str(e)}"
            )

    def _remove_llm(self):
        """Remove LLM agent from the chat"""
        if not self.llm_agent.is_active():
            self.message_handler.add_system_message(
                "No AI assistant currently active in the chat."
            )
            return

        ai_name = self.llm_agent.get_name()
        self.llm_agent.deactivate()
        if ai_name:
            self.message_handler.add_message(
                "SYSTEM", f"AI assistant {ai_name} is no longer available.", "ai_event"
            )

    def _set_llm_model(self, model_name: str):
        """Set the LLM model"""
        if not self.llm_agent.is_active():
            self.message_handler.add_system_message(
                "No AI assistant currently active. Use /llm invite first."
            )
            return

        try:
            self.llm_agent.set_model(model_name)
        except Exception as e:
            self.message_handler.add_system_message(f"Failed to set model: {str(e)}")

    def _send_llm_command_to_host(self, args: List[str]):
        """Send LLM command to host via network"""
        if not self.network_manager:
            self.message_handler.add_system_message(
                "Cannot send command to host: no network connection"
            )
            return

        # Send special LLM command message to host
        command_data = {
            "type": "llm_command",
            "username": self.current_user,
            "command": args,
            "timestamp": time.time(),
        }

        if (
            hasattr(self.network_manager, "server_connection")
            and self.network_manager.server_connection
        ):
            try:
                import json

                self.network_manager.server_connection.send(
                    json.dumps(command_data).encode()
                )
                # Show local feedback
                subcommand = args[0].lower()
                if subcommand == "invite":
                    name_part = f" {args[1]}" if len(args) > 1 else ""
                    self.message_handler.add_system_message(
                        f"Requesting host to invite AI assistant{name_part}..."
                    )
                elif subcommand == "leave":
                    self.message_handler.add_system_message(
                        "Requesting host to remove AI assistant..."
                    )
                elif subcommand == "model":
                    model_name = args[1] if len(args) > 1 else "?"
                    self.message_handler.add_system_message(
                        f"Requesting host to change AI model to {model_name}..."
                    )
            except Exception as e:
                self.message_handler.add_system_message(
                    f"Failed to send command to host: {str(e)}"
                )
        else:
            self.message_handler.add_system_message(
                "Not connected to host to send LLM command"
            )

    def _process_llm_command_from_peer(self, message_data):
        """Process LLM command received from a peer (host only)"""
        peer_username = message_data.get("username", "Unknown")
        command_args = message_data.get("command", [])

        if not command_args:
            return

        subcommand = command_args[0].lower()

        # Show who initiated the command
        if subcommand == "invite":
            custom_name = command_args[1] if len(command_args) > 1 else None
            self.message_handler.add_system_message(
                f"{peer_username} requested to invite AI assistant"
            )
            self._invite_llm(custom_name)
        elif subcommand == "leave":
            self.message_handler.add_system_message(
                f"{peer_username} requested to remove AI assistant"
            )
            self._remove_llm()
        elif subcommand == "model":
            if len(command_args) > 1:
                model_name = command_args[1]
                self.message_handler.add_system_message(
                    f"{peer_username} requested to change AI model to {model_name}"
                )
                self._set_llm_model(model_name)
            else:
                self.message_handler.add_system_message(
                    f"{peer_username} requested model change but didn't specify model"
                )
        else:
            self.message_handler.add_system_message(
                f"{peer_username} sent unknown LLM command: {subcommand}"
            )

    def _show_help(self):
        """Show help message"""
        help_text = """Available commands:
/help - Show this help message
/quit or /exit - Leave the chat
/clear - Clear message history and screen
/stats - Show chat statistics
/users - Show connected users
/llm invite [name] - Invite AI assistant to chat (with optional custom name)
/llm leave - Remove AI assistant from chat
/llm model <model_name> - Change AI model (e.g., gpt-4, claude-3, etc.)

Note: AI assistant runs on host's computer and responds to everyone"""

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
        if self.network_manager:
            peers = self.network_manager.get_connected_peers()
            if peers:
                users_text = "Connected users:\n"
                for peer in peers:
                    users_text += f"• {peer.username}@{peer.hostname} (online)\n"
                users_text += f"• {self.current_user} (you)"
            else:
                users_text = (
                    f"Connected users:\n• {self.current_user} (you - hosting)"
                    if self.is_host
                    else f"Connected users:\n• {self.current_user} (you)"
                )
        else:
            users_text = f"Connected users:\n• {self.current_user} (you - no network)"

        # Add AI assistant if active
        if self.llm_agent and self.llm_agent.is_active():
            ai_name = self.llm_agent.get_name()
            users_text += f"\n• 🤖 {ai_name} (AI assistant)"

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

    def _handle_network_event(self, event_type: str, data):
        """Handle network events and convert them to chat messages"""
        if event_type == "peer_joined":
            peer_info = data
            self.message_handler.add_message(
                "SYSTEM", f"{peer_info.username} joined the chat", "user_event"
            )
        elif event_type == "peer_left":
            peer_info = data
            self.message_handler.add_message(
                "SYSTEM", f"{peer_info.username} left the chat", "user_event"
            )
        elif event_type == "message_received":
            message_data = data
            if message_data.get("type") == "chat_message":
                self.message_handler.add_message(
                    message_data["username"],
                    message_data["content"],
                    message_data.get("timestamp"),
                )
            elif message_data.get("type") == "llm_command" and self.is_host:
                # Host processes LLM commands from peers
                self._process_llm_command_from_peer(message_data)

    def _get_username_color(self, username: str) -> str:
        """Get a consistent color for a username"""
        if username == self.current_user:
            return "\033[1;32m"  # Your messages always in green
        elif username == "SYSTEM" or username == "System":
            return "\033[1;33m"  # System messages in yellow
        elif (
            self.llm_agent
            and self.llm_agent.is_active()
            and username == self.llm_agent.get_name()
        ):
            return "\033[1;35m"  # AI assistant in magenta
        else:
            # Assign a unique color to each username
            if username not in self.username_colors:
                self.username_colors[username] = self.available_colors[
                    self.color_index % len(self.available_colors)
                ]
                self.color_index += 1
            return self.username_colors[username]

    def _format_message(self, msg: ChatMessage) -> str:
        """Format a single message for display"""
        timestamp = datetime.fromtimestamp(msg.timestamp).strftime("%H:%M:%S")

        if msg.message_type == "system":
            return f"\033[33m[{timestamp}] * {msg.content}\033[0m"
        elif msg.message_type == "user_event":
            return f"\033[36m[{timestamp}] ▶ {msg.content}\033[0m"
        elif msg.message_type == "ai_event":
            return f"\033[95m[{timestamp}] 🤖 {msg.content}\033[0m"
        else:
            # Regular chat messages
            color = self._get_username_color(msg.username)

            if msg.username == self.current_user:
                # Your messages
                return f"\033[90m[{timestamp}]\033[0m {color}{msg.username}:\033[0m {msg.content}"
            elif msg.username == "SYSTEM" or msg.username == "System":
                # System messages with special formatting
                return f"\033[90m[{timestamp}]\033[0m {color}* {msg.content}\033[0m"
            elif (
                self.llm_agent
                and self.llm_agent.is_active()
                and msg.username == self.llm_agent.get_name()
            ):
                # AI assistant messages with robot emoji
                return f"\033[90m[{timestamp}]\033[0m {color}🤖 {msg.username}:\033[0m {msg.content}"
            else:
                # Other users with their assigned colors
                return f"\033[90m[{timestamp}]\033[0m {color}{msg.username}:\033[0m {msg.content}"
