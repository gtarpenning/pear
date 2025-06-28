"""
Network Core - Consolidated P2P networking with clean separation of concerns
"""

import socket
import threading
import time
import json
import uuid
from typing import List, Dict, Optional, Tuple, Any, Callable
from dataclasses import dataclass
from rich.console import Console

console = Console()


@dataclass
class PeerInfo:
    """Information about a connected peer"""
    id: str
    hostname: str
    ip_address: str
    port: int
    username: str
    connected_at: float


@dataclass
class SessionInfo:
    """Information about a chat session"""
    name: str
    host: str
    host_ip: str
    port: int
    user_count: int
    created_at: float


@dataclass
class NetworkConfig:
    """Network configuration settings"""
    discovery_ports: List[int]
    message_ports: List[int]
    broadcast_addresses: List[str]
    timeout_seconds: int = 10
    retry_attempts: int = 3


class NetworkUtils:
    """Utility functions for network operations"""
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def get_broadcast_addresses() -> List[str]:
        """Get broadcast addresses for the local network"""
        addresses = ["255.255.255.255"]  # Global broadcast
        try:
            local_ip = NetworkUtils.get_local_ip()
            if local_ip != "127.0.0.1":
                parts = local_ip.split('.')
                if len(parts) == 4:
                    # Calculate network broadcast
                    network_broadcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                    if network_broadcast not in addresses:
                        addresses.append(network_broadcast)
        except Exception:
            pass
        return addresses
    
    @staticmethod
    def is_port_available(port: int, host: str = '') -> bool:
        """Check if a port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((host, port))
                return True
        except OSError:
            return False
    
    @staticmethod
    def find_available_port(preferred_ports: List[int], host: str = '') -> Optional[int]:
        """Find the first available port from a list"""
        for port in preferred_ports:
            if NetworkUtils.is_port_available(port, host):
                return port
        return None


class ConfigDetector:
    """Detects network configuration and environment"""
    
    @staticmethod
    def detect_network_config() -> NetworkConfig:
        """Detect optimal network configuration"""
        if ConfigDetector._is_corporate_environment():
            console.print("[yellow]Corporate network detected[/yellow]")
            return NetworkConfig(
                discovery_ports=[8888, 3000, 5000, 9000],
                message_ports=[8889, 3001, 5001, 9001],
                broadcast_addresses=NetworkUtils.get_broadcast_addresses(),
                timeout_seconds=15,
                retry_attempts=5
            )
        else:
            return NetworkConfig(
                discovery_ports=[8888, 8890, 8891],
                message_ports=[8889, 8892, 8893],
                broadcast_addresses=NetworkUtils.get_broadcast_addresses()
            )
    
    @staticmethod
    def _is_corporate_environment() -> bool:
        """Conservative corporate environment detection"""
        import os
        
        # Only detect corporate if we have strong indicators
        # Don't be aggressive about home networks
        
        # Check for proxy environment variables (strong indicator)
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        if any(os.environ.get(var) for var in proxy_vars):
            return True
        
        # Check hostname for corporate patterns (conservative)
        hostname = socket.gethostname().lower()
        corporate_patterns = ['corp', 'company', 'enterprise', 'office', 'work']
        if any(pattern in hostname for pattern in corporate_patterns):
            return True
        
        # Don't flag based on IP ranges alone - too many false positives
        # Home networks commonly use 192.168.x.x, 10.x.x.x etc.
        
        return False


class DiscoveryService:
    """Handles session discovery via UDP broadcast"""
    
    def __init__(self, config: NetworkConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.discovered_sessions: Dict[str, SessionInfo] = {}
        self.session_name: Optional[str] = None
        
    def start(self, session_name: str) -> bool:
        """Start discovery service"""
        self.session_name = session_name
        
        # Try each discovery port until we find one that works
        for port in self.config.discovery_ports:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.socket.settimeout(1.0)  # Add timeout for discovery socket
                self.socket.bind(('', port))
                
                self.running = True
                self.thread = threading.Thread(target=self._listen_loop, daemon=True)
                self.thread.start()
                
                console.print(f"[green]Discovery service started on port {port}[/green]")
                return True
                
            except Exception as e:
                # Close the socket and try the next port
                if self.socket:
                    self.socket.close()
                    self.socket = None
                console.print(f"[dim]Port {port} unavailable: {e}[/dim]")
                continue
        
        console.print("[yellow]All discovery ports unavailable[/yellow]")
        return False
    
    def discover_sessions(self) -> List[SessionInfo]:
        """Discover available sessions"""
        self.discovered_sessions.clear()
        
        for port in self.config.discovery_ports:
            self._send_discovery_request(port)
        
        time.sleep(1)  # Wait for responses
        return list(self.discovered_sessions.values())
    
    def _send_discovery_request(self, port: int):
        """Send discovery request to a specific port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(1.0)
                
                request = json.dumps({"type": "discovery_request"})
                
                for addr in self.config.broadcast_addresses:
                    try:
                        s.sendto(request.encode(), (addr, port))
                    except Exception:
                        continue
                        
        except Exception as e:
            console.print(f"[dim]Discovery request failed on port {port}: {e}[/dim]")
    
    def _listen_loop(self):
        """Listen for discovery messages"""
        while self.running and self.socket:
            try:
                data, addr = self.socket.recvfrom(1024)
                self._handle_discovery_message(data, addr)
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    break
    
    def _handle_discovery_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming discovery message"""
        try:
            message = json.loads(data.decode())
            
            if message.get("type") == "discovery_request" and self.session_name:
                # Respond with session info
                response = {
                    "type": "session_info",
                    "session_name": self.session_name,
                    "host": socket.gethostname(),
                    "host_ip": NetworkUtils.get_local_ip(),
                    "port": 8889,  # Default message port
                    "user_count": 1,
                    "created_at": time.time()
                }
                
                self.socket.sendto(json.dumps(response).encode(), addr)
                
            elif message.get("type") == "session_info":
                # Store discovered session
                session = SessionInfo(
                    name=message["session_name"],
                    host=message["host"],
                    host_ip=message["host_ip"],
                    port=message["port"],
                    user_count=message["user_count"],
                    created_at=message["created_at"]
                )
                self.discovered_sessions[session.name] = session
                
        except Exception:
            pass
    
    def stop(self):
        """Stop discovery service"""
        self.running = False
        if self.socket:
            self.socket.close()
            self.socket = None


class MessageServer:
    """Handles TCP message connections"""
    
    def __init__(self, config: NetworkConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.peer_connections: Dict[str, socket.socket] = {}
        self.message_callbacks: List[Callable] = []
        
    def start(self) -> bool:
        """Start message server"""
        port = NetworkUtils.find_available_port(self.config.message_ports)
        
        if not port:
            console.print("[red]No message ports available[/red]")
            return False
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('', port))
            self.socket.listen(10)
            
            self.running = True
            self.thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.thread.start()
            
            console.print(f"[green]Message server started on port {port}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Failed to start message server: {e}[/red]")
            return False
    
    def add_message_callback(self, callback: Callable):
        """Add callback for incoming messages"""
        self.message_callbacks.append(callback)
    
    def broadcast_message(self, message: dict, exclude_peer: Optional[str] = None):
        """Broadcast message to all connected peers"""
        data = json.dumps(message).encode()
        
        for peer_id, connection in self.peer_connections.items():
            if peer_id != exclude_peer:
                try:
                    connection.send(data + b'\n')
                except Exception:
                    self._disconnect_peer(peer_id)
    
    def _accept_loop(self):
        """Accept incoming connections"""
        while self.running and self.socket:
            try:
                client_socket, addr = self.socket.accept()
                threading.Thread(
                    target=self._handle_peer,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except Exception:
                if self.running:
                    break
    
    def _handle_peer(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle a peer connection"""
        peer_id = str(uuid.uuid4())
        self.peer_connections[peer_id] = client_socket
        
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode().strip())
                    for callback in self.message_callbacks:
                        callback("message_received", message)
                except json.JSONDecodeError:
                    continue
                    
        except Exception:
            pass
        finally:
            self._disconnect_peer(peer_id)
    
    def _disconnect_peer(self, peer_id: str):
        """Disconnect a peer"""
        if peer_id in self.peer_connections:
            try:
                self.peer_connections[peer_id].close()
            except Exception:
                pass
            del self.peer_connections[peer_id]
    
    def stop(self):
        """Stop message server"""
        self.running = False
        if self.socket:
            self.socket.close()
            self.socket = None
        
        for connection in self.peer_connections.values():
            try:
                connection.close()
            except Exception:
                pass
        self.peer_connections.clear()


class NetworkManager:
    """Main network manager with clean separation of concerns"""
    
    def __init__(self):
        self.config = ConfigDetector.detect_network_config()
        self.discovery_service = DiscoveryService(self.config)
        self.message_server = MessageServer(self.config)
        self.session_name: Optional[str] = None
        self.is_host = False
        
    def create_session(self, session_name: str) -> bool:
        """Create and host a session"""
        self.session_name = session_name
        self.is_host = True
        
        # Start message server first (required for chat to work)
        server_ok = self.message_server.start()
        if not server_ok:
            console.print("[red]Failed to start message server - cannot create session[/red]")
            return False
        
        # Try to start discovery (nice to have, but not required)
        discovery_ok = self.discovery_service.start(session_name)
        if not discovery_ok:
            console.print("[yellow]⚠ Discovery service failed - session not discoverable[/yellow]")
            console.print("[cyan]Others can still connect directly using:[/cyan]")
            console.print(f"[white]  pear connect {self.get_local_ip()}[/white]")
        
        console.print(f"[green]Session '{session_name}' created successfully[/green]")
        return True
    
    def discover_sessions(self) -> List[SessionInfo]:
        """Discover available sessions"""
        return self.discovery_service.discover_sessions()
    
    def connect_to_session(self, session_name: str) -> bool:
        """Connect to an existing session"""
        sessions = self.discover_sessions()
        
        for session in sessions:
            if session.name == session_name:
                return self._connect_direct(session.host_ip, session.port)
        
        return False
    
    def connect_direct(self, host_ip: str, port: int) -> bool:
        """Connect directly to a host"""
        return self._connect_direct(host_ip, port)
    
    def _connect_direct(self, host_ip: str, port: int) -> bool:
        """Internal direct connection method"""
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(self.config.timeout_seconds)
            client_socket.connect((host_ip, port))
            
            # Handle incoming messages
            threading.Thread(
                target=self._handle_server_messages,
                args=(client_socket,),
                daemon=True
            ).start()
            
            console.print(f"[green]Connected to {host_ip}:{port}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return False
    
    def _handle_server_messages(self, server_socket: socket.socket):
        """Handle messages from server"""
        try:
            while True:
                data = server_socket.recv(1024)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode().strip())
                    for callback in self.message_server.message_callbacks:
                        callback("message_received", message)
                except json.JSONDecodeError:
                    continue
                    
        except Exception:
            pass
    
    def send_message(self, message: str, username: str):
        """Send a message"""
        msg_data = {
            "type": "chat_message",
            "username": username,
            "content": message,
            "timestamp": time.time()
        }
        
        if self.is_host:
            self.message_server.broadcast_message(msg_data)
        # Client sending would need server connection handling
    
    def add_message_callback(self, callback: Callable):
        """Add message callback"""
        self.message_server.add_message_callback(callback)
    
    def stop(self):
        """Stop all network services"""
        self.discovery_service.stop()
        self.message_server.stop()
    
    def get_local_ip(self) -> str:
        """Get local IP"""
        return NetworkUtils.get_local_ip()
    
    def get_local_hostname(self) -> str:
        """Get local hostname"""
        return socket.gethostname() 