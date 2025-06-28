"""
CLI Commands - Clean command handlers for Pear Chat
"""

from typing import Optional, List
from rich.console import Console
from rich.panel import Panel

from .network_core import NetworkManager, SessionInfo
from .message_system import MessageHandler
from .simple_terminal_ui import SimpleTerminalInterface
from .config import PearConfig


class SessionCommands:
    """Commands for session management"""
    
    def __init__(self, console: Console, network_manager: NetworkManager):
        self.console = console
        self.network_manager = network_manager
    
    def start_session(self, session_name: Optional[str], username: str) -> bool:
        """Start hosting a session"""
        if not session_name:
            session_name = f"session_{self.network_manager.get_local_hostname()}"
        
        self.console.print(f"[cyan]Starting session: {session_name}[/cyan]")
        
        success = self.network_manager.create_session(session_name)
        if success:
            self.console.print(f"[green]Session '{session_name}' started successfully[/green]")
            self._show_connection_info()
        else:
            self.console.print("[red]Failed to start session[/red]")
            
        return success
    
    def join_session(self, session_name: Optional[str]) -> Optional[str]:
        """Join an existing session, returns the session name if successful"""
        if not session_name:
            return self._select_session_interactively()
        
        self.console.print(f"[cyan]Joining session: {session_name}[/cyan]")
        success = self.network_manager.connect_to_session(session_name)
        
        if success:
            self.console.print(f"[green]Joined session '{session_name}'[/green]")
            return session_name
        else:
            self.console.print(f"[red]Failed to join session '{session_name}'[/red]")
            return None
    
    def connect_direct(self, target: str) -> bool:
        """Connect directly to a host"""
        host, port = self._parse_target(target)
        self.console.print(f"[cyan]Connecting to {host}:{port}[/cyan]")
        
        success = self.network_manager.connect_direct(host, port)
        if not success:
            self._show_connection_troubleshooting(host, port)
            
        return success
    
    def list_sessions(self) -> List[SessionInfo]:
        """List and optionally join available sessions"""
        sessions = self.network_manager.discover_sessions()
        
        if not sessions:
            self.console.print("[yellow]No active sessions found[/yellow]")
            return sessions
        
        self._display_sessions(sessions)
        return sessions
    
    def _select_session_interactively(self) -> Optional[str]:
        """Let user select from available sessions"""
        sessions = self.list_sessions()
        if not sessions:
            return None
        
        if len(sessions) == 1:
            return self._prompt_single_session(sessions[0])
        else:
            return self._prompt_multiple_sessions(sessions)
    
    def _prompt_single_session(self, session: SessionInfo) -> Optional[str]:
        """Handle single session selection"""
        self.console.print(
            f"[green]Found session: {session.name} (host: {session.host}, users: {session.user_count})[/green]"
        )
        
        try:
            response = input("\nJoin this session? (y/n): ").strip().lower()
            return session.name if response == 'y' else None
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled[/yellow]")
            return None
    
    def _prompt_multiple_sessions(self, sessions: List[SessionInfo]) -> Optional[str]:
        """Handle multiple session selection"""
        try:
            choice = int(input("Select session number (0 to cancel): ")) - 1
            if 0 <= choice < len(sessions):
                return sessions[choice].name
            else:
                self.console.print("[red]Invalid selection[/red]")
                return None
        except (ValueError, KeyboardInterrupt):
            self.console.print("\n[yellow]Cancelled[/yellow]")
            return None
    
    def _display_sessions(self, sessions: List[SessionInfo]):
        """Display available sessions"""
        self.console.print("[cyan]Available sessions:[/cyan]")
        for i, session in enumerate(sessions, 1):
            self.console.print(
                f"  {i}. {session.name} (host: {session.host}, users: {session.user_count})"
            )
    
    def _parse_target(self, target: str) -> tuple[str, int]:
        """Parse target address, return (host, port)"""
        if ':' in target:
            parts = target.split(':')
            try:
                return parts[0], int(parts[1])
            except (ValueError, IndexError):
                self.console.print("[red]Invalid port in target address[/red]")
                return target, 8889
        return target, 8889
    
    def _show_connection_info(self):
        """Show connection information for hosted session"""
        local_ip = self.network_manager.get_local_ip()
        self.console.print(f"[dim]Local IP for direct connections: {local_ip}:8889[/dim]")
    
    def _show_connection_troubleshooting(self, host: str, port: int):
        """Show troubleshooting tips for failed connections"""
        self.console.print("[yellow]Connection troubleshooting:[/yellow]")
        self.console.print(f"  • Verify {host} is hosting a session")
        self.console.print(f"  • Check if port {port} is correct")
        self.console.print("  • Ensure no firewall is blocking the connection")


class ConfigCommands:
    """Commands for configuration management"""
    
    def __init__(self, console: Console, config: PearConfig):
        self.console = console
        self.config = config
    
    def set_username(self, username: Optional[str]) -> str:
        """Set username, prompt if not provided"""
        if not username:
            username = self._prompt_username()
        
        self.config.set_username(username)
        self.console.print(f"[green]Username set to: {username}[/green]")
        return username
    
    def show_config(self):
        """Display current configuration"""
        config_data = self.config.get_all()
        
        if not config_data:
            self.console.print("[yellow]No configuration set[/yellow]")
            return
        
        self.console.print("[cyan]Current Configuration:[/cyan]")
        for key, value in config_data.items():
            self.console.print(f"  {key}: {value}")
    
    def _prompt_username(self) -> str:
        """Prompt user for username"""
        try:
            username = input("Enter username: ").strip()
            return username or "user"
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled, using default username[/yellow]")
            return "user"


class ChatCommands:
    """Commands for starting chat interfaces"""
    
    def __init__(self, username: str):
        self.username = username
    
    def start_chat_interface(self, session_name: str, is_host: bool, 
                           network_manager: NetworkManager) -> None:
        """Start the chat interface"""
        message_handler = MessageHandler()
        terminal_ui = SimpleTerminalInterface(self.username)
        
        terminal_ui.start_chat_interface(
            session_name=session_name,
            is_host=is_host,
            message_handler=message_handler,
            network_manager=network_manager,
        )


class HelpCommands:
    """Commands for help and information"""
    
    def __init__(self, console: Console):
        self.console = console
    
    def show_help(self):
        """Display help information"""
        help_text = """
[bold cyan]Pear Chat Commands:[/bold cyan]

[yellow]Basic Usage:[/yellow]
  pear start [session_name]    - Start hosting a session
  pear join [session_name]     - Join a session (auto-discover if no name)
  pear list                    - List available sessions
  pear connect <ip:port>       - Connect directly to a host

[yellow]Configuration:[/yellow]
  pear login [username]        - Set your username
  pear config                  - Show current configuration

[yellow]Help:[/yellow]
  pear help                    - Show this help message

[yellow]Examples:[/yellow]
  pear start mysession         - Start session named 'mysession'
  pear join                    - Show available sessions to join
  pear connect 192.168.1.100   - Connect directly to IP
  pear login alice             - Set username to 'alice'
        """
        
        panel = Panel(help_text, title="Pear Chat Help", border_style="cyan")
        self.console.print(panel) 