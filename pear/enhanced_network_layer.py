#!/usr/bin/env python3
"""
Enhanced Network Layer with Corporate Network Support
Includes fallback mechanisms and better diagnostics
"""

import sys
import socket
import threading
import time
import json
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
import os
from rich.console import Console

console = Console()


@dataclass
class NetworkConfig:
    """Network configuration settings"""
    discovery_ports: List[int]
    message_ports: List[int]
    enable_upnp: bool = False
    proxy_settings: Optional[Dict[str, str]] = None
    corporate_mode: bool = False
    timeout_seconds: int = 10
    retry_attempts: int = 3


@dataclass
class ConnectionAttempt:
    """Details about a connection attempt"""
    protocol: str
    target: str
    port: int
    success: bool
    error_message: Optional[str] = None
    duration_ms: int = 0


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
    discovery_method: str = "udp_broadcast"


class NetworkProtocol:
    """Base class for network protocols"""
    
    def __init__(self, name: str):
        self.name = name
        self.active = False
    
    async def discover_sessions(self) -> List[SessionInfo]:
        raise NotImplementedError
    
    async def connect_to_session(self, session_info: SessionInfo) -> bool:
        raise NotImplementedError
    
    def send_message(self, message: dict) -> bool:
        raise NotImplementedError


class DirectP2PProtocol(NetworkProtocol):
    """Original direct P2P protocol"""
    
    def __init__(self, config: NetworkConfig):
        super().__init__("Direct P2P")
        self.config = config
        self.local_ip = self._get_local_ip()
        
    def _get_local_ip(self) -> str:
        """Get local IP address with multiple fallback methods"""
        methods = [
            ("external_connection", lambda: self._get_ip_via_external()),
            ("interface_scan", lambda: self._get_ip_via_interfaces()),
            ("hostname_resolve", lambda: socket.gethostbyname(socket.gethostname())),
        ]
        
        for method_name, method_func in methods:
            try:
                ip = method_func()
                if ip and ip != "127.0.0.1":
                    console.print(f"[dim]Got local IP via {method_name}: {ip}[/dim]")
                    return ip
            except Exception as e:
                console.print(f"[dim]Failed to get IP via {method_name}: {e}[/dim]")
                continue
        
        return "127.0.0.1"
    
    def _get_ip_via_external(self) -> str:
        """Get IP by connecting to external service"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    
    def _get_ip_via_interfaces(self) -> str:
        """Get IP by scanning network interfaces"""
        import subprocess
        try:
            if sys.platform == "win32":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                # Parse Windows ipconfig output
                for line in result.stdout.split('\n'):
                    if 'IPv4 Address' in line:
                        ip = line.split(':')[-1].strip()
                        if not ip.startswith('127.'):
                            return ip
            else:
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                ips = result.stdout.strip().split()
                for ip in ips:
                    if not ip.startswith('127.'):
                        return ip
        except Exception:
            pass
        return None


class EnhancedNetworkManager:
    """Enhanced network manager with corporate network support"""
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        self.local_hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()
        self.config = config or self._get_default_config()
        self.session_name = None
        self.is_host = False
        self.peers: Dict[str, PeerInfo] = {}
        self.running = False
        
        # Connection tracking
        self.connection_attempts: List[ConnectionAttempt] = []
        self.last_error: Optional[str] = None
        self.network_diagnostics: Dict[str, Any] = {}
        
        # Protocol support
        self.protocols = []
        self._initialize_protocols()
        
        # Original components (for backward compatibility)
        self.discovery_socket: Optional[socket.socket] = None
        self.discovery_thread: Optional[threading.Thread] = None
        self.message_server: Optional[socket.socket] = None
        self.message_thread: Optional[threading.Thread] = None
        self.peer_connections: Dict[str, socket.socket] = {}
        self.message_callbacks: List = []
        self.discovered_sessions: Dict[str, SessionInfo] = {}
    
    def _get_default_config(self) -> NetworkConfig:
        """Get default network configuration"""
        # Detect if we're in a corporate environment
        corporate_indicators = self._detect_corporate_environment()
        
        if corporate_indicators["is_corporate"]:
            console.print("[yellow]Corporate network detected - using corporate-friendly settings[/yellow]")
            return NetworkConfig(
                discovery_ports=[8888, 3000, 5000, 9000, 8080],
                message_ports=[8889, 3001, 5001, 9001, 8081],
                corporate_mode=True,
                timeout_seconds=15,
                retry_attempts=5
            )
        else:
            return NetworkConfig(
                discovery_ports=[8888, 8890, 8891],
                message_ports=[8889, 8892, 8893],
                corporate_mode=False,
                timeout_seconds=10,
                retry_attempts=3
            )
    
    def _detect_corporate_environment(self) -> Dict[str, Any]:
        """Detect if we're in a corporate network environment"""
        indicators = {
            "is_corporate": False,
            "confidence": 0,
            "reasons": []
        }
        
        # Check for proxy environment variables
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        if any(os.environ.get(var) for var in proxy_vars):
            indicators["confidence"] += 30
            indicators["reasons"].append("Proxy environment variables detected")
        
        # Check IP range (corporate networks often use specific ranges)
        ip_parts = self.local_ip.split('.')
        if ip_parts[0] == '10':  # Class A private
            indicators["confidence"] += 20
            indicators["reasons"].append("Class A private IP range (10.x.x.x)")
        elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:  # Class B private
            indicators["confidence"] += 25
            indicators["reasons"].append("Class B private IP range (172.16-31.x.x)")
        
        # Check hostname patterns
        hostname_lower = self.local_hostname.lower()
        corporate_patterns = ['corp', 'company', 'enterprise', 'office', 'work']
        for pattern in corporate_patterns:
            if pattern in hostname_lower:
                indicators["confidence"] += 15
                indicators["reasons"].append(f"Corporate hostname pattern: {pattern}")
                break
        
        # Check if UDP broadcast is likely to be blocked
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(1.0)
                # Try to send a test broadcast
                s.sendto(b"test", ("255.255.255.255", 12345))
        except Exception:
            indicators["confidence"] += 20
            indicators["reasons"].append("UDP broadcast appears to be blocked")
        
        indicators["is_corporate"] = indicators["confidence"] >= 40
        return indicators
    
    def _initialize_protocols(self):
        """Initialize available network protocols"""
        self.protocols = [
            DirectP2PProtocol(self.config),
            # Future: WebSocketProtocol(self.config),
            # Future: RelayProtocol(self.config),
        ]
    
    def _get_local_ip(self) -> str:
        """Get local IP address with enhanced detection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def _record_connection_attempt(self, protocol: str, target: str, port: int, 
                                 success: bool, error: Optional[str] = None, 
                                 duration_ms: int = 0):
        """Record details of a connection attempt for diagnostics"""
        attempt = ConnectionAttempt(
            protocol=protocol,
            target=target,
            port=port,
            success=success,
            error_message=error,
            duration_ms=duration_ms
        )
        self.connection_attempts.append(attempt)
        
        if not success:
            self.last_error = error
            console.print(f"[red]Connection failed: {protocol} to {target}:{port} - {error}[/red]")
        else:
            console.print(f"[green]Connection successful: {protocol} to {target}:{port}[/green]")
    
    def create_session(self, session_name: str):
        """Create and host a new chat session with enhanced error handling"""
        self.session_name = session_name
        self.is_host = True
        
        console.print(f"[cyan]Creating session: {session_name}[/cyan]")
        
        # Try to start services with port flexibility
        discovery_started = self._start_discovery_service_flexible()
        message_server_started = self._start_message_server_flexible()
        
        if discovery_started and message_server_started:
            console.print(f"[green]✓ Session '{session_name}' created successfully[/green]")
            return True
        else:
            error_msg = "Failed to start required services"
            if not discovery_started:
                error_msg += " (discovery service failed)"
            if not message_server_started:
                error_msg += " (message server failed)"
            
            console.print(f"[red]✗ {error_msg}[/red]")
            console.print("[yellow]💡 Try running the network debugger to identify issues[/yellow]")
            return False
    
    def _start_discovery_service_flexible(self) -> bool:
        """Start discovery service with port flexibility"""
        for port in self.config.discovery_ports:
            try:
                console.print(f"[dim]Trying discovery service on port {port}...[/dim]")
                
                self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.discovery_socket.bind(("", port))
                
                self.running = True
                
                # Update config with successful port
                self.config.discovery_ports = [port] + [p for p in self.config.discovery_ports if p != port]
                
                # Start discovery listener thread
                self.discovery_thread = threading.Thread(target=self._discovery_listener)
                self.discovery_thread.daemon = True
                self.discovery_thread.start()
                
                console.print(f"[green]✓ Discovery service started on port {port}[/green]")
                self._record_connection_attempt("UDP Discovery", "localhost", port, True)
                return True
                
            except Exception as e:
                error_msg = str(e)
                console.print(f"[yellow]Port {port} unavailable: {error_msg}[/yellow]")
                self._record_connection_attempt("UDP Discovery", "localhost", port, False, error_msg)
                
                if self.discovery_socket:
                    try:
                        self.discovery_socket.close()
                    except:
                        pass
                    self.discovery_socket = None
                continue
        
        console.print("[red]✗ All discovery ports failed[/red]")
        return False
    
    def _start_message_server_flexible(self) -> bool:
        """Start message server with port flexibility"""
        for port in self.config.message_ports:
            try:
                console.print(f"[dim]Trying message server on port {port}...[/dim]")
                
                self.message_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.message_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.message_server.bind(("", port))
                self.message_server.listen(10)
                
                # Update config with successful port
                self.config.message_ports = [port] + [p for p in self.config.message_ports if p != port]
                
                self.message_thread = threading.Thread(target=self._message_server_loop)
                self.message_thread.daemon = True
                self.message_thread.start()
                
                console.print(f"[green]✓ Message server started on port {port}[/green]")
                self._record_connection_attempt("TCP Server", "localhost", port, True)
                return True
                
            except Exception as e:
                error_msg = str(e)
                console.print(f"[yellow]Port {port} unavailable: {error_msg}[/yellow]")
                self._record_connection_attempt("TCP Server", "localhost", port, False, error_msg)
                
                if self.message_server:
                    try:
                        self.message_server.close()
                    except:
                        pass
                    self.message_server = None
                continue
        
        console.print("[red]✗ All message server ports failed[/red]")
        return False
    
    def discover_sessions_enhanced(self) -> List[SessionInfo]:
        """Enhanced session discovery with multiple methods and better error reporting"""
        console.print("[cyan]🔍 Discovering sessions with enhanced methods...[/cyan]")
        
        discovered = []
        discovery_methods = [
            ("UDP Broadcast", self._discover_via_udp_broadcast),
            ("Direct Scan", self._discover_via_direct_scan),
            # Future: ("mDNS", self._discover_via_mdns),
            # Future: ("HTTP", self._discover_via_http),
        ]
        
        for method_name, method_func in discovery_methods:
            try:
                console.print(f"[dim]Trying {method_name} discovery...[/dim]")
                sessions = method_func()
                if sessions:
                    console.print(f"[green]✓ {method_name}: Found {len(sessions)} session(s)[/green]")
                    discovered.extend(sessions)
                else:
                    console.print(f"[yellow]○ {method_name}: No sessions found[/yellow]")
            except Exception as e:
                console.print(f"[red]✗ {method_name}: Failed - {str(e)}[/red]")
                self._record_connection_attempt(method_name, "broadcast", 0, False, str(e))
        
        # Remove duplicates
        unique_sessions = {}
        for session in discovered:
            key = f"{session.name}_{session.host_ip}_{session.port}"
            if key not in unique_sessions:
                unique_sessions[key] = session
        
        final_sessions = list(unique_sessions.values())
        console.print(f"[cyan]Discovery complete: {len(final_sessions)} unique session(s) found[/cyan]")
        
        return final_sessions
    
    def _discover_via_udp_broadcast(self) -> List[SessionInfo]:
        """Original UDP broadcast discovery"""
        sessions = []
        
        for port in self.config.discovery_ports:
            try:
                discovery_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                discovery_sock.settimeout(2.0)
                
                discovery_request = {
                    "type": "discovery_request",
                    "requester": self.local_hostname,
                    "requester_ip": self.local_ip,
                    "timestamp": time.time(),
                }
                
                request_data = json.dumps(discovery_request).encode()
                broadcast_ip = self._get_broadcast_address()
                
                discovery_sock.sendto(request_data, (broadcast_ip, port))
                
                # Listen for responses
                start_time = time.time()
                while time.time() - start_time < 1.5:
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
                                discovery_method="udp_broadcast"
                            )
                            sessions.append(session_info)
                    except socket.timeout:
                        break
                    except json.JSONDecodeError:
                        continue
                
                discovery_sock.close()
                break  # If successful, don't try other ports
                
            except Exception:
                if discovery_sock:
                    discovery_sock.close()
                continue
        
        return sessions
    
    def _discover_via_direct_scan(self) -> List[SessionInfo]:
        """Direct IP scanning for local network (fallback method)"""
        sessions = []
        
        if self.config.corporate_mode:
            # Skip direct scanning in corporate mode for security
            return sessions
        
        # Scan local subnet for active chat servers
        ip_base = '.'.join(self.local_ip.split('.')[:-1]) + '.'
        
        # Only scan a few IPs to avoid being too intrusive
        scan_range = [1, 100, 101, 102, 200, 254]  # Common IPs
        
        for last_octet in scan_range:
            target_ip = ip_base + str(last_octet)
            if target_ip == self.local_ip:
                continue
            
            for port in self.config.message_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)  # Very short timeout
                        result = s.connect_ex((target_ip, port))
                        if result == 0:  # Connection successful
                            # Found something - could be a chat server
                            session_info = SessionInfo(
                                name=f"Direct-{target_ip}",
                                host=target_ip,
                                host_ip=target_ip,
                                port=port,
                                user_count=1,
                                created_at=time.time(),
                                discovery_method="direct_scan"
                            )
                            sessions.append(session_info)
                except Exception:
                    continue
        
        return sessions
    
    def _get_broadcast_address(self) -> str:
        """Calculate broadcast address for current network"""
        try:
            ip_parts = self.local_ip.split(".")
            ip_parts[-1] = "255"
            return ".".join(ip_parts)
        except:
            return "255.255.255.255"
    
    def get_diagnostics(self) -> Dict[str, Any]:
        """Get network diagnostics information"""
        return {
            "local_ip": self.local_ip,
            "local_hostname": self.local_hostname,
            "config": {
                "discovery_ports": self.config.discovery_ports,
                "message_ports": self.config.message_ports,
                "corporate_mode": self.config.corporate_mode,
            },
            "connection_attempts": [
                {
                    "protocol": attempt.protocol,
                    "target": attempt.target,
                    "port": attempt.port,
                    "success": attempt.success,
                    "error": attempt.error_message,
                    "duration_ms": attempt.duration_ms
                }
                for attempt in self.connection_attempts
            ],
            "last_error": self.last_error,
            "active_connections": len(self.peer_connections),
            "session_info": {
                "name": self.session_name,
                "is_host": self.is_host,
                "peer_count": len(self.peers)
            }
        }
    
    # Include all the original methods for backward compatibility
    def _discovery_listener(self):
        """Listen for UDP discovery requests and respond with session info"""
        while self.running and self.discovery_socket:
            try:
                data, address = self.discovery_socket.recvfrom(1024)
                message = json.loads(data.decode())

                if message["type"] == "discovery_request":
                    if self.session_name and self.is_host:
                        response = {
                            "type": "session_info",
                            "session_name": self.session_name,
                            "host": self.local_hostname,
                            "host_ip": self.local_ip,
                            "port": self.config.message_ports[0],  # Use first available port
                            "user_count": len(self.peers) + 1,
                            "created_at": time.time(),
                        }
                        response_data = json.dumps(response).encode()
                        if self.discovery_socket:
                            self.discovery_socket.sendto(response_data, address)

            except json.JSONDecodeError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    console.print(f"[yellow]Discovery listener error: {e}[/yellow]")
    
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
    
    def _handle_peer_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle individual peer connection with enhanced error reporting"""
        peer_id = None
        try:
            client_socket.settimeout(1.0)
            
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
                        
                        response = {"type": "join_ack", "status": "success"}
                        client_socket.send(json.dumps(response).encode())
                        
                        console.print(f"[green]✓ Peer joined: {peer_info.hostname} ({peer_info.ip_address})[/green]")
                        self._record_connection_attempt("Peer Join", address[0], address[1], True)

                    elif message["type"] == "chat_message":
                        # Broadcast to other peers
                        for other_peer_id, connection in self.peer_connections.items():
                            if other_peer_id != peer_id:
                                try:
                                    connection.send(json.dumps(message).encode())
                                except:
                                    pass  # Handle disconnected peers later

                except socket.timeout:
                    continue
                except json.JSONDecodeError:
                    console.print("[yellow]Received invalid message format[/yellow]")
                    continue

        except Exception as e:
            error_msg = f"Peer connection error from {address[0]}:{address[1]}: {e}"
            console.print(f"[yellow]{error_msg}[/yellow]")
            self._record_connection_attempt("Peer Connection", address[0], address[1], False, str(e))
        finally:
            if peer_id and peer_id in self.peers:
                del self.peers[peer_id]
                console.print(f"[yellow]Peer disconnected: {peer_id}[/yellow]")
            if peer_id and peer_id in self.peer_connections:
                del self.peer_connections[peer_id]
            try:
                client_socket.close()
            except:
                pass
    
    def add_message_callback(self, callback):
        """Add callback for message events"""
        self.message_callbacks.append(callback)
    
    def stop(self):
        """Stop all network services"""
        console.print("[cyan]Stopping enhanced network services...[/cyan]")
        self.running = False

        if self.discovery_socket:
            try:
                self.discovery_socket.close()
            except:
                pass
            self.discovery_socket = None

        if self.message_server:
            try:
                self.message_server.close()
            except:
                pass
            self.message_server = None

        for connection in self.peer_connections.values():
            try:
                connection.close()
            except:
                pass
        self.peer_connections.clear()
        self.peers.clear()
        self.discovered_sessions.clear()
        self.session_name = None