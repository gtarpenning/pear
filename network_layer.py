"""
Network Layer - P2P networking components
Handles discovery, connections, and message routing
"""

import socket
import threading
import time
import json
import struct
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import uuid
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


class NetworkManager:
    """Manages P2P networking for chat sessions"""
    
    def __init__(self):
        self.local_hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()
        self.discovery_port = 8888
        self.message_port = 8889
        self.session_name = None
        self.is_host = False
        self.peers: Dict[str, PeerInfo] = {}
        self.running = False
        
        # UDP discovery components
        self.discovery_socket: Optional[socket.socket] = None
        self.discovery_thread: Optional[threading.Thread] = None
        self.broadcast_thread: Optional[threading.Thread] = None
        self.discovered_sessions: Dict[str, SessionInfo] = {}
        
    def _get_local_ip(self) -> str:
        """Get the local IP address"""
        try:
            # Create a socket and connect to a remote address to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def get_local_hostname(self) -> str:
        """Get the local hostname"""
        return self.local_hostname
    
    def create_session(self, session_name: str):
        """Create and host a new chat session"""
        self.session_name = session_name
        self.is_host = True
        console.print(f"[green]Created session: {session_name}[/green]")
    
    def start_discovery_service(self):
        """Start the UDP discovery service for broadcasting session availability"""
        console.print(f"[cyan]Starting UDP discovery service on port {self.discovery_port}[/cyan]")
        self.running = True
        
        try:
            # Create UDP socket for discovery
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.discovery_socket.bind(('', self.discovery_port))
            
            # Start discovery listener thread
            self.discovery_thread = threading.Thread(target=self._discovery_listener)
            self.discovery_thread.daemon = True
            self.discovery_thread.start()
            
            # Start session broadcast thread if we're hosting
            if self.session_name:
                self.broadcast_thread = threading.Thread(target=self._session_broadcaster)
                self.broadcast_thread.daemon = True
                self.broadcast_thread.start()
                
        except Exception as e:
            console.print(f"[red]Failed to start discovery service: {e}[/red]")
            self.running = False
    
    def _discovery_listener(self):
        """Listen for UDP discovery requests and respond with session info"""
        while self.running and self.discovery_socket:
            try:
                data, address = self.discovery_socket.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message['type'] == 'discovery_request':
                    # Respond with our session info if we're hosting
                    if self.session_name and self.is_host:
                        response = {
                            'type': 'session_info',
                            'session_name': self.session_name,
                            'host': self.local_hostname,
                            'host_ip': self.local_ip,
                            'port': self.message_port,
                            'user_count': len(self.peers) + 1,  # +1 for host
                            'created_at': time.time()
                        }
                        response_data = json.dumps(response).encode()
                        if self.discovery_socket:
                            self.discovery_socket.sendto(response_data, address)
                        
                elif message['type'] == 'session_info':
                    # Store discovered session info
                    session_info = SessionInfo(
                        name=message['session_name'],
                        host=message['host'],
                        host_ip=message['host_ip'],
                        port=message['port'],
                        user_count=message['user_count'],
                        created_at=message['created_at']
                    )
                    self.discovered_sessions[session_info.name] = session_info
                    
            except json.JSONDecodeError:
                continue  # Invalid message format
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only log if we're still supposed to be running
                    console.print(f"[yellow]Discovery listener error: {e}[/yellow]")
    
    def _session_broadcaster(self):
        """Periodically broadcast our session information"""
        while self.running and self.session_name:
            try:
                broadcast_message = {
                    'type': 'session_announce',
                    'session_name': self.session_name,
                    'host': self.local_hostname,
                    'host_ip': self.local_ip,
                    'port': self.message_port,
                    'user_count': len(self.peers) + 1,
                    'created_at': time.time()
                }
                message_data = json.dumps(broadcast_message).encode()
                
                # Broadcast to entire subnet
                broadcast_ip = self._get_broadcast_address()
                if self.discovery_socket:
                    self.discovery_socket.sendto(message_data, (broadcast_ip, self.discovery_port))
                
                time.sleep(5)  # Broadcast every 5 seconds
                
            except Exception as e:
                console.print(f"[yellow]Broadcast error: {e}[/yellow]")
                time.sleep(5)
    
    def _get_broadcast_address(self) -> str:
        """Calculate broadcast address for current network"""
        try:
            # Simple approach: assume /24 network
            ip_parts = self.local_ip.split('.')
            ip_parts[-1] = '255'
            return '.'.join(ip_parts)
        except:
            return '255.255.255.255'  # Fallback to limited broadcast
    
    def start_message_server(self):
        """Start the message server for handling peer connections"""
        print(f"[MOCK] Starting message server on port {self.message_port}")
        
        # In a real implementation, this would start a TCP server
        # that accepts connections from peers and handles message routing
        server_thread = threading.Thread(target=self._mock_message_server)
        server_thread.daemon = True
        server_thread.start()
    
    def _mock_message_server(self):
        """Mock message server that simulates peer connections"""
        while self.running:
            # Simulate handling peer connections
            time.sleep(1)
    
    def discover_sessions(self) -> List[SessionInfo]:
        """Discover active chat sessions on the network via UDP broadcast"""
        console.print("[cyan]Discovering sessions on network...[/cyan]")
        
        # Clear previous discoveries
        self.discovered_sessions.clear()
        
        try:
            # Create temporary discovery socket
            discovery_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            discovery_sock.settimeout(3.0)  # 3 second timeout for responses
            
            # Send discovery request
            discovery_request = {
                'type': 'discovery_request',
                'requester': self.local_hostname,
                'requester_ip': self.local_ip,
                'timestamp': time.time()
            }
            
            request_data = json.dumps(discovery_request).encode()
            broadcast_ip = self._get_broadcast_address()
            
            # Send to broadcast address
            discovery_sock.sendto(request_data, (broadcast_ip, self.discovery_port))
            console.print(f"  [dim]Sent discovery request to {broadcast_ip}:{self.discovery_port}[/dim]")
            
            # Listen for responses
            start_time = time.time()
            while time.time() - start_time < 3.0:  # Listen for 3 seconds
                try:
                    data, address = discovery_sock.recvfrom(1024)
                    response = json.loads(data.decode())
                    
                    if response['type'] == 'session_info':
                        session_info = SessionInfo(
                            name=response['session_name'],
                            host=response['host'],
                            host_ip=response['host_ip'],
                            port=response['port'],
                            user_count=response['user_count'],
                            created_at=response['created_at']
                        )
                        self.discovered_sessions[session_info.name] = session_info
                        console.print(f"  [green]Found session: {session_info.name} on {session_info.host}[/green]")
                        
                except socket.timeout:
                    break
                except json.JSONDecodeError:
                    continue
                    
            discovery_sock.close()
            
        except Exception as e:
            console.print(f"[red]Discovery error: {e}[/red]")
        
        # Convert to list format expected by CLI
        sessions = []
        for session_info in self.discovered_sessions.values():
            sessions.append({
                'name': session_info.name,
                'host': session_info.host,
                'host_ip': session_info.host_ip,
                'port': session_info.port,
                'user_count': session_info.user_count
            })
        
        console.print(f"[cyan]Discovery complete. Found {len(sessions)} session(s)[/cyan]")
        return sessions
    
    def connect_to_session(self, session_name: str) -> bool:
        """Connect to an existing chat session"""
        print(f"[MOCK] Connecting to session: {session_name}")
        
        # Mock connection logic
        time.sleep(1)  # Simulate connection delay
        
        # Simulate successful connection
        self.session_name = session_name
        self.is_host = False
        
        # Add mock peer (the host)
        host_peer = PeerInfo(
            id=str(uuid.uuid4()),
            hostname="session-host",
            ip_address="192.168.1.100",
            port=8889,
            username="host_user",
            connected_at=time.time()
        )
        self.peers[host_peer.id] = host_peer
        
        print(f"[MOCK] Successfully connected to {session_name}")
        return True
    
    def send_message(self, message: str, username: str):
        """Send a message to all connected peers"""
        print(f"[MOCK] Broadcasting message from {username}: {message}")
        
        # In a real implementation, this would send the message
        # to all connected peers via TCP connections
        
        # Mock message broadcast
        message_data = {
            'type': 'message',
            'username': username,
            'content': message,
            'timestamp': time.time()
        }
        
        # Simulate sending to all peers
        for peer_id, peer in self.peers.items():
            print(f"[MOCK] Sending to peer {peer.hostname}: {message_data}")
    
    def add_peer(self, peer_info: PeerInfo):
        """Add a new peer to the session"""
        self.peers[peer_info.id] = peer_info
        print(f"[MOCK] Peer joined: {peer_info.username}@{peer_info.hostname}")
    
    def remove_peer(self, peer_id: str):
        """Remove a peer from the session"""
        if peer_id in self.peers:
            peer = self.peers[peer_id]
            del self.peers[peer_id]
            print(f"[MOCK] Peer left: {peer.username}@{peer.hostname}")
    
    def get_connected_peers(self) -> List[PeerInfo]:
        """Get list of currently connected peers"""
        return list(self.peers.values())
    
    def stop(self):
        """Stop all network services"""
        console.print("[cyan]Stopping network services...[/cyan]")
        self.running = False
        
        # Close discovery socket
        if self.discovery_socket:
            try:
                self.discovery_socket.close()
            except:
                pass
            self.discovery_socket = None
        
        # Clear session data
        self.peers.clear()
        self.discovered_sessions.clear()
        self.session_name = None 