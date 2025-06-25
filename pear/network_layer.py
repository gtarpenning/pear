"""
Network Layer - P2P networking components
Handles discovery, connections, and message routing
"""

import sys
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

        # TCP message server components
        self.message_server: Optional[socket.socket] = None
        self.message_thread: Optional[threading.Thread] = None
        self.peer_connections: Dict[str, socket.socket] = {}
        self.message_callbacks: List = []

        # Client connection for non-hosts
        self.server_connection: Optional[socket.socket] = None

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
        console.print(
            f"[cyan]Starting UDP discovery service on port {self.discovery_port}[/cyan]"
        )
        self.running = True

        try:
            # Create UDP socket for discovery
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.discovery_socket.bind(("", self.discovery_port))

            # Start discovery listener thread
            self.discovery_thread = threading.Thread(target=self._discovery_listener)
            self.discovery_thread.daemon = True
            self.discovery_thread.start()

            # Start session broadcast thread if we're hosting
            if self.session_name:
                self.broadcast_thread = threading.Thread(
                    target=self._session_broadcaster
                )
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

                if message["type"] == "discovery_request":
                    # Respond with our session info if we're hosting
                    if self.session_name and self.is_host:
                        response = {
                            "type": "session_info",
                            "session_name": self.session_name,
                            "host": self.local_hostname,
                            "host_ip": self.local_ip,
                            "port": self.message_port,
                            "user_count": len(self.peers) + 1,  # +1 for host
                            "created_at": time.time(),
                        }
                        response_data = json.dumps(response).encode()
                        if self.discovery_socket:
                            self.discovery_socket.sendto(response_data, address)

                elif message["type"] == "session_info":
                    # Store discovered session info
                    session_info = SessionInfo(
                        name=message["session_name"],
                        host=message["host"],
                        host_ip=message["host_ip"],
                        port=message["port"],
                        user_count=message["user_count"],
                        created_at=message["created_at"],
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
                    "type": "session_announce",
                    "session_name": self.session_name,
                    "host": self.local_hostname,
                    "host_ip": self.local_ip,
                    "port": self.message_port,
                    "user_count": len(self.peers) + 1,
                    "created_at": time.time(),
                }
                message_data = json.dumps(broadcast_message).encode()

                # Broadcast to entire subnet
                broadcast_ip = self._get_broadcast_address()
                if self.discovery_socket:
                    self.discovery_socket.sendto(
                        message_data, (broadcast_ip, self.discovery_port)
                    )

                time.sleep(5)  # Broadcast every 5 seconds

            except Exception as e:
                console.print(f"[yellow]Broadcast error: {e}[/yellow]")
                time.sleep(5)

    def _get_broadcast_address(self) -> str:
        """Calculate broadcast address for current network"""
        try:
            # Simple approach: assume /24 network
            ip_parts = self.local_ip.split(".")
            ip_parts[-1] = "255"
            return ".".join(ip_parts)
        except:
            return "255.255.255.255"  # Fallback to limited broadcast

    def start_message_server(self):
        """Start the TCP message server for handling peer connections"""
        if not self.running:
            return

        console.print(
            f"[cyan]Starting TCP message server on port {self.message_port}[/cyan]"
        )

        try:
            self.message_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.message_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.message_server.bind(("", self.message_port))
            self.message_server.listen(10)

            self.message_thread = threading.Thread(target=self._message_server_loop)
            self.message_thread.daemon = True
            self.message_thread.start()

        except Exception as e:
            console.print(f"[red]Failed to start message server: {e}[/red]")

    def _message_server_loop(self):
        """Main message server loop accepting peer connections"""
        while self.running and self.message_server:
            try:
                client_socket, address = self.message_server.accept()

                client_thread = threading.Thread(
                    target=self._handle_peer_connection, args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

            except socket.error:
                if self.running:
                    console.print("[yellow]Message server socket error[/yellow]")
                break

    def _handle_peer_connection(
        self, client_socket: socket.socket, address: Tuple[str, int]
    ):
        """Handle individual peer connection"""
        peer_id = None
        try:
            client_socket.settimeout(1.0)  # Short timeout for checking running state

            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    message = json.loads(data.decode())

                    if message["type"] == "peer_join":
                        peer_id = message["peer_id"]
                        peer_info = PeerInfo(
                            id=peer_id,
                            hostname=message["hostname"],
                            ip_address=address[0],
                            port=address[1],
                            username=message["username"],
                            connected_at=time.time(),
                        )
                        self.peers[peer_id] = peer_info
                        self.peer_connections[peer_id] = client_socket
                        self._notify_callbacks("peer_joined", peer_info)

                        response = {"type": "join_ack", "status": "success"}
                        client_socket.send(json.dumps(response).encode())

                    elif message["type"] == "chat_message":
                        self._broadcast_message(message, exclude_peer=peer_id)
                        self._notify_callbacks("message_received", message)

                except socket.timeout:
                    # Timeout is expected, just continue checking if still running
                    continue
                except json.JSONDecodeError:
                    console.print(
                        "[yellow]Received invalid message format from peer[/yellow]"
                    )
                    continue

        except Exception as e:
            console.print(
                f"[yellow]Peer connection error from {address[0]}:{address[1]}: {e}[/yellow]"
            )
        finally:
            if peer_id:
                self._disconnect_peer(peer_id)
            try:
                client_socket.close()
            except:
                pass

    def _broadcast_message(self, message: dict, exclude_peer: Optional[str] = None):
        """Broadcast message to all connected peers except sender"""
        disconnected_peers = []

        for peer_id, connection in self.peer_connections.items():
            if peer_id == exclude_peer:
                continue

            try:
                connection.send(json.dumps(message).encode())
            except:
                disconnected_peers.append(peer_id)

        for peer_id in disconnected_peers:
            self._disconnect_peer(peer_id)

    def _disconnect_peer(self, peer_id: str):
        """Disconnect and clean up peer"""
        if peer_id in self.peers:
            peer_info = self.peers[peer_id]
            del self.peers[peer_id]
            self._notify_callbacks("peer_left", peer_info)

        if peer_id in self.peer_connections:
            try:
                self.peer_connections[peer_id].close()
            except:
                pass
            del self.peer_connections[peer_id]

    def add_message_callback(self, callback):
        """Add callback for message events"""
        self.message_callbacks.append(callback)

    def _notify_callbacks(self, event_type: str, data):
        """Notify all registered callbacks"""
        for callback in self.message_callbacks:
            try:
                callback(event_type, data)
            except:
                pass

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
                "type": "discovery_request",
                "requester": self.local_hostname,
                "requester_ip": self.local_ip,
                "timestamp": time.time(),
            }

            request_data = json.dumps(discovery_request).encode()
            broadcast_ip = self._get_broadcast_address()

            # Send to broadcast address
            discovery_sock.sendto(request_data, (broadcast_ip, self.discovery_port))
            console.print(
                f"  [dim]Sent discovery request to {broadcast_ip}:{self.discovery_port}[/dim]"
            )

            # Listen for responses
            start_time = time.time()
            while time.time() - start_time < 1.0:  # Listen for 1 second
                try:
                    data, address = discovery_sock.recvfrom(1024)
                    response = json.loads(data.decode())

                    if response["type"] == "session_info":
                        session_info = SessionInfo(
                            name=response["session_name"],
                            host=response["host"],
                            host_ip=response["host_ip"],
                            port=response["port"],
                            user_count=response["user_count"],
                            created_at=response["created_at"],
                        )
                        self.discovered_sessions[session_info.name] = session_info
                        console.print(
                            f"  [green]Found session: {session_info.name} on {session_info.host}[/green]"
                        )

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
            sessions.append(
                {
                    "name": session_info.name,
                    "host": session_info.host,
                    "host_ip": session_info.host_ip,
                    "port": session_info.port,
                    "user_count": session_info.user_count,
                }
            )

        console.print(
            f"[cyan]Discovery complete. Found {len(sessions)} session(s)[/cyan]"
        )
        return sessions

    def connect_to_session(self, session_name: str) -> bool:
        """Connect to an existing chat session via TCP"""
        if session_name not in self.discovered_sessions:
            console.print(
                f"[yellow]Session '{session_name}' not found, running discovery...[/yellow]"
            )
            self.discover_sessions()

            if session_name not in self.discovered_sessions:
                console.print(
                    f"[red]Session '{session_name}' not found after discovery[/red]"
                )
                return False

        session_info = self.discovered_sessions[session_name]
        console.print(
            f"[cyan]Connecting to session: {session_name} at {session_info.host_ip}:{session_info.port}[/cyan]"
        )

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10.0)  # Only for initial connection
            client_socket.connect((session_info.host_ip, session_info.port))

            peer_id = str(uuid.uuid4())
            join_message = {
                "type": "peer_join",
                "peer_id": peer_id,
                "hostname": self.local_hostname,
                "username": self.local_hostname,
                "session_name": session_name,
            }

            client_socket.send(json.dumps(join_message).encode())

            response_data = client_socket.recv(1024)
            response = json.loads(response_data.decode())

            if response.get("status") == "success":
                self.session_name = session_name
                self.is_host = False

                # Remove timeout for ongoing connection and store the server connection
                client_socket.settimeout(None)
                self.server_connection = client_socket

                # Start running state for client
                self.running = True

                client_thread = threading.Thread(
                    target=self._handle_server_messages, args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()

                console.print(
                    f"[green]Successfully connected to {session_name}[/green]"
                )
                return True
            else:
                console.print(f"[red]Connection rejected by host[/red]")
                client_socket.close()
                return False

        except Exception as e:
            console.print(f"[red]Failed to connect to session: {e}[/red]")
            return False

    def _handle_server_messages(self, server_socket: socket.socket):
        """Handle messages from the session host"""
        try:
            server_socket.settimeout(1.0)  # Short timeout for checking running state
            while self.running:
                try:
                    data = server_socket.recv(4096)
                    if not data:
                        console.print("[yellow]Server connection closed[/yellow]")
                        sys.exit(0)

                    message = json.loads(data.decode())
                    self._notify_callbacks("message_received", message)

                except socket.timeout:
                    # Timeout is expected, just continue checking if still running
                    continue
                except json.JSONDecodeError:
                    console.print("[yellow]Received invalid message format[/yellow]")
                    continue

        except Exception as e:
            console.print(f"[yellow]Server connection error: {e}[/yellow]")
        finally:
            # Clean up connection
            try:
                server_socket.close()
            except:
                pass
            if hasattr(self, "server_connection"):
                self.server_connection = None

    def send_message(self, message: str, username: str):
        """Send a message to all connected peers via TCP"""
        message_data = {
            "type": "chat_message",
            "username": username,
            "content": message,
            "timestamp": time.time(),
        }

        if self.is_host:
            self._broadcast_message(message_data)
        else:
            # For clients, send directly to server connection
            if hasattr(self, "server_connection") and self.server_connection:
                try:
                    self.server_connection.send(json.dumps(message_data).encode())
                except Exception as e:
                    console.print(
                        f"[yellow]Failed to send message to host: {e}[/yellow]"
                    )
            else:
                console.print("[yellow]Not connected to any session[/yellow]")

    def add_peer(self, peer_info: PeerInfo):
        """Add a new peer to the session"""
        self.peers[peer_info.id] = peer_info

    def remove_peer(self, peer_id: str):
        """Remove a peer from the session"""
        if peer_id in self.peers:
            peer = self.peers[peer_id]
            del self.peers[peer_id]

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

        # Close message server
        if self.message_server:
            try:
                self.message_server.close()
            except:
                pass
            self.message_server = None

        # Close server connection (for clients)
        if self.server_connection:
            try:
                self.server_connection.close()
            except:
                pass
            self.server_connection = None

        # Close all peer connections
        for connection in self.peer_connections.values():
            try:
                connection.close()
            except:
                pass
        self.peer_connections.clear()

        # Clear session data
        self.peers.clear()
        self.discovered_sessions.clear()
        self.session_name = None
