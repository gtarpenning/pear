"""
Terminal UI - Simple scrolling chat interface using Rich library
"""

import time
from typing import Optional, List
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.align import Align
from rich.box import ROUNDED
from rich.prompt import Prompt
from rich.rule import Rule
from rich.columns import Columns

from message_system import MessageHandler, ChatMessage


class TerminalInterface:
    """Simple scrolling terminal interface for chat"""
    
    def __init__(self):
        self.console = Console()
        self.running = False
        self.current_user = None
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
        
        # Show startup banner
        self._show_chat_header()
        
        # Add welcome messages
        if is_host:
            message_handler.add_system_message(f"Started chat session: {session_name}")
            message_handler.add_system_message(f"You are hosting this session")
        else:
            message_handler.add_system_message(f"Joined chat session: {session_name}")
        
        message_handler.add_system_message(f"Welcome {self.current_user}! Type /help for commands")
        
        # Set up message callback to display new messages
        message_handler.add_message_callback(self._on_new_message)
        
        # Display initial messages
        self._display_recent_messages()
        
        # Start the input loop
        self._run_input_loop()
    
    def _get_username(self) -> str:
        """Get username from user"""
        try:
            username = Prompt.ask(
                "[bold cyan]Enter your username[/bold cyan]",
                default="user"
            )
            return username
        except KeyboardInterrupt:
            return "user"

    def _show_chat_header(self):
        """Show the chat session header"""
        self.console.clear()
        
        title = f"🍐 Pear Chat - {self.session_name}"
        subtitle = "Host" if self.is_host else "Participant"
        
        header_text = Text()
        header_text.append(title, style="bold cyan")
        header_text.append(f" ({subtitle})", style="dim")
        
        header_panel = Panel(
            Align.center(header_text),
            box=ROUNDED,
            style="cyan"
        )
        
        self.console.print(header_panel)
        self.console.print()
        
        # Show help hint
        help_text = Text()
        help_text.append("💬 Type your message and press Enter • ", style="dim")
        help_text.append("/help", style="yellow")
        help_text.append(" for commands • ", style="dim")
        help_text.append("/quit", style="red")
        help_text.append(" to exit", style="dim")
        
        self.console.print(Align.center(help_text))
        self.console.print(Rule(style="dim"))
        self.console.print()

    def _display_recent_messages(self, limit: int = 10):
        """Display recent messages"""
        messages = self.message_handler.get_messages(limit=limit)
        
        for msg in messages:
            self._display_message(msg)
        
        self.last_message_count = len(self.message_handler.get_messages())

    def _display_message(self, msg: ChatMessage):
        """Display a single message"""
        timestamp = msg.formatted_time()
        
        if msg.message_type == "system":
            # System message in yellow
            text = Text()
            text.append(f"[{timestamp}] ", style="dim")
            text.append("* ", style="yellow bold")
            text.append(msg.content, style="yellow")
            self.console.print(text)
        else:
            # User message
            text = Text()
            text.append(f"[{timestamp}] ", style="dim")
            
            if msg.username == self.current_user:
                text.append(f"{msg.username}: ", style="bold cyan")
            else:
                text.append(f"{msg.username}: ", style="bold green")
            
            text.append(msg.content, style="white")
            self.console.print(text)

    def _on_new_message(self, message: ChatMessage):
        """Callback for when a new message arrives"""
        # Display the new message immediately
        self._display_message(message)
        self.last_message_count += 1

    def _run_input_loop(self):
        """Main input loop"""
        while self.running:
            try:
                self.console.print()  # Add space before input
                
                # Create input prompt
                user_input = Prompt.ask(
                    f"[bold cyan]{self.current_user}[/bold cyan]",
                    default="",
                    show_default=False
                ).strip()
                
                if user_input:
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
        
        # Cleanup
        self._show_goodbye()

    def _show_goodbye(self):
        """Show goodbye message"""
        self.console.print()
        self.console.print("[yellow]👋 Thanks for using Pear Chat![/yellow]")
        if self.is_host:
            self.console.print("[dim]Chat session ended[/dim]")

    def _handle_command(self, command: str):
        """Handle chat commands"""
        cmd_parts = command[1:].split()
        cmd = cmd_parts[0].lower()
        
        if cmd == "help":
            self._show_help()
        elif cmd == "quit" or cmd == "exit":
            self.running = False
        elif cmd == "clear":
            self._clear_chat()
        elif cmd == "stats":
            self._show_stats()
        elif cmd == "users":
            self._show_users()
        else:
            self.message_handler.add_system_message(f"Unknown command: {command}")

    def _show_help(self):
        """Show help message"""
        self.console.print()
        help_panel = Panel(
            """[bold]Available Commands:[/bold]

[yellow]/help[/yellow]     - Show this help message
[yellow]/quit[/yellow]     - Leave the chat
[yellow]/clear[/yellow]    - Clear chat history
[yellow]/stats[/yellow]    - Show chat statistics
[yellow]/users[/yellow]    - Show connected users

Just type your message and press Enter to chat!""",
            title="💡 Help",
            box=ROUNDED,
            border_style="yellow"
        )
        self.console.print(help_panel)

    def _clear_chat(self):
        """Clear the chat display"""
        self.console.clear()
        self._show_chat_header()
        self.message_handler.clear_messages()
        self.message_handler.add_system_message("Chat history cleared")

    def _show_stats(self):
        """Show chat statistics"""
        stats = self.message_handler.get_message_stats()
        
        stats_table = Table(box=ROUNDED, border_style="blue")
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value", style="cyan")
        
        stats_table.add_row("Total Messages", str(stats['total_messages']))
        stats_table.add_row("Unique Users", str(stats['unique_users']))
        
        if stats['first_message_time']:
            start_time = datetime.fromtimestamp(stats['first_message_time']).strftime('%H:%M:%S')
            stats_table.add_row("Session Started", start_time)
        
        self.console.print()
        self.console.print(Panel(stats_table, title="📊 Chat Statistics", border_style="blue"))

    def _show_users(self):
        """Show connected users"""
        # Mock user list for now - this would be replaced with real network data
        users_table = Table(box=ROUNDED, border_style="green")
        users_table.add_column("User", style="bold")
        users_table.add_column("Status", justify="center")
        
        users_table.add_row(f"{self.current_user} (you)", "🟢 Online")
        users_table.add_row("alice", "🟢 Online")
        users_table.add_row("bob", "🟡 Typing")
        
        self.console.print()
        self.console.print(Panel(users_table, title="👥 Connected Users", border_style="green"))

    def show_session_list(self, sessions: List[dict]):
        """Show available sessions in a nice format"""
        if not sessions:
            self.console.print("[yellow]No active sessions found on the network[/yellow]")
            return
        
        self.console.print("\n[bold cyan]Available Chat Sessions[/bold cyan]")
        self.console.print()
        
        table = Table(box=ROUNDED, border_style="cyan")
        table.add_column("Session Name", style="bold green")
        table.add_column("Host", style="blue")
        table.add_column("Users", justify="center", style="yellow")
        table.add_column("Status", justify="center")
        
        for session in sessions:
            status = "🟢 Active"
            table.add_row(
                session['name'],
                session['host'],
                str(session['user_count']),
                status
            )
        
        self.console.print(table)
        self.console.print()

    def show_connection_status(self, session_name: str, success: bool):
        """Show connection status"""
        if success:
            self.console.print(f"[green]✅ Successfully connected to {session_name}[/green]")
        else:
            self.console.print(f"[red]❌ Failed to connect to {session_name}[/red]")

    def show_startup_banner(self):
        """Show the startup banner"""
        banner = """
[bold cyan]🍐 Pear - P2P Terminal Chat[/bold cyan]
[dim]Real-time messaging on your local network[/dim]
        """
        self.console.print(Panel(Align.center(banner), box=ROUNDED, border_style="cyan"))
        self.console.print() 