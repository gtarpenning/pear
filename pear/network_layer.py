"""
Network Layer - P2P networking components
Handles discovery, connections, and message routing
Enhanced with flexible port binding and corporate network support
"""

import sys
import socket
import threading
import time
import json
import os
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
import uuid
from rich.console import Console

from .network_analyzer import NetworkAnalyzer, NetworkConfig

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
    """Manages P2P networking for chat sessions with enhanced flexibility"""

    def __init__(self):
        self.local_hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()
        
        # Network analysis and intelligent configuration
        self.network_analyzer = NetworkAnalyzer()
        self.network_config: Optional[NetworkConfig] = None
        self._smart_configure_network()
        
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
        
        # Enhanced diagnostics
        self.connection_attempts: List = []
        self.last_error: Optional[str] = None

    def _smart_configure_network(self):
        """Intelligently configure network based on analysis"""
        try:
            self.network_config = self.network_analyzer.analyze_network()
            
            # Use recommended ports from analysis
            self.discovery_ports = self.network_config.port_recommendations["discovery"]
            self.message_ports = self.network_config.port_recommendations["messaging"]
            
            # Set primary ports
            self.discovery_port = self.discovery_ports[0]
            self.message_port = self.message_ports[0]
            
            # Determine if this is a challenging network environment
            self.corporate_mode = self.network_config.confidence_score < 70
            
            # Use analyzed broadcast addresses
            self.broadcast_addresses = self.network_config.broadcast_addresses
            
            if self.network_config.discovery_strategy == "direct_connection_only":
                console.print("[yellow]⚠ Network broadcast not available - direct connections recommended[/yellow]")
                console.print(f"[cyan]Your IP for direct connections: {self.network_config.primary_interface.ip_address}[/cyan]")
                
        except Exception as e:
            console.print(f"[yellow]Network analysis failed, using fallback configuration: {e}[/yellow]")
            self._configure_ports_fallback()
    
    def _configure_ports_fallback(self):
        """Fallback port configuration when analysis fails"""
        corporate_indicators = self._detect_corporate_environment()
        
        if corporate_indicators["is_corporate"]:
            console.print("[yellow]Corporate network detected - using flexible port configuration[/yellow]")
            self.discovery_ports = [8888, 3000, 5000, 9000, 8080]
            self.message_ports = [8889, 3001, 5001, 9001, 8081]
            self.corporate_mode = True
        else:
            self.discovery_ports = [8888, 8890, 8891]
            self.message_ports = [8889, 8892, 8893]
            self.corporate_mode = False
        
        # Set primary ports for backward compatibility
        self.discovery_port = self.discovery_ports[0]
        self.message_port = self.message_ports[0]
        
        # Use basic broadcast addresses as fallback
        self.broadcast_addresses = self._get_broadcast_addresses()

    def _detect_corporate_environment(self) -> Dict[str, Any]:
        """Detect if we're in a corporate network environment"""
        indicators: Dict[str, Any] = {
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
        try:
            ip_parts = self.local_ip.split('.')
            if len(ip_parts) >= 2:
                if ip_parts[0] == '10':  # Class A private
                    indicators["confidence"] += 20
                    indicators["reasons"].append("Class A private IP range (10.x.x.x)")
                elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:  # Class B private
                    indicators["confidence"] += 25
                    indicators["reasons"].append("Class B private IP range (172.16-31.x.x)")
        except (ValueError, IndexError):
            pass
        
        # Check hostname patterns
        hostname_lower = self.local_hostname.lower()
        corporate_patterns = ['corp', 'company', 'enterprise', 'office', 'work']
        for pattern in corporate_patterns:
            if pattern in hostname_lower:
                indicators["confidence"] += 15
                indicators["reasons"].append(f"Corporate hostname pattern: {pattern}")
                break
        
        indicators["is_corporate"] = indicators["confidence"] >= 40
        return indicators

    def _get_local_ip(self) -> str:
        """Get the local IP address with enhanced detection"""
        try:
            # Create a socket and connect to a remote address to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _record_connection_attempt(self, protocol: str, target: str, port: int, 
                                 success: bool, error: Optional[str] = None):
        """Record connection attempt for diagnostics"""
        attempt = {
            "protocol": protocol,
            "target": target,
            "port": port,
            "success": success,
            "error": error,
            "timestamp": time.time()
        }
        self.connection_attempts.append(attempt)
        
        if not success:
            self.last_error = error
            console.print(f"[red]Connection failed: {protocol} to {target}:{port} - {error}[/red]")
        else:
            console.print(f"[green]Connection successful: {protocol} to {target}:{port}[/green]")

    def get_local_hostname(self) -> str:
        """Get the local hostname"""
        return self.local_hostname

    def create_session(self, session_name: str):
        """Create and host a new chat session"""
        self.session_name = session_name
        self.is_host = True
        console.print(f"[green]Created session: {session_name}[/green]")
        console.print(f"[dim]  └─ Host: {self.local_hostname} ({self.local_ip})[/dim]")

    def start_discovery_service(self):
        """Start the UDP discovery service with flexible port binding"""
        console.print("[cyan]Starting UDP discovery service with flexible port binding[/cyan]")
        self.running = True

        # Try ports in order of preference
        for port in self.discovery_ports:
            try:
                console.print(f"[dim]Trying discovery service on port {port}...[/dim]")
                
                # Create UDP socket for discovery
                self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.discovery_socket.bind(("", port))

                # Update the primary port to the successful one
                self.discovery_port = port
                
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
        self.running = False
        return False

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
        """Periodically broadcast our session information with multiple fallback addresses"""
        broadcast_failure_count = 0
        max_consecutive_failures = 3
        
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

                # Use intelligently determined broadcast addresses
                broadcast_addresses = getattr(self, 'broadcast_addresses', self._get_broadcast_addresses())
                broadcast_success = False
                
                for broadcast_ip in broadcast_addresses:
                    try:
                        if self.discovery_socket:
                            self.discovery_socket.sendto(
                                message_data, (broadcast_ip, self.discovery_port)
                            )
                            broadcast_success = True
                            # If successful, don't try other addresses this round
                            break
                    except Exception as e:
                        # Only log individual broadcast failures in debug mode
                        if broadcast_failure_count < max_consecutive_failures:
                            console.print(f"[dim]Broadcast to {broadcast_ip} failed: {e}[/dim]")
                        continue

                if broadcast_success:
                    broadcast_failure_count = 0
                else:
                    broadcast_failure_count += 1
                    if broadcast_failure_count >= max_consecutive_failures:
                        console.print("[yellow]⚠ Broadcast failing on this network - sessions may not be discoverable[/yellow]")
                        console.print("[dim]  └─ Consider using direct connection with IP address[/dim]")
                        # Reduce broadcast frequency after repeated failures
                        time.sleep(15)
                        continue

                time.sleep(5)  # Broadcast every 5 seconds

            except Exception as e:
                console.print(f"[yellow]Broadcast error: {e}[/yellow]")
                time.sleep(5)

    def _get_broadcast_addresses(self) -> List[str]:
        """Get multiple potential broadcast addresses for better network compatibility"""
        addresses = []
        
        try:
            ip_parts = self.local_ip.split(".")
            
            # Try different common subnet configurations
            subnet_configs = [
                # /24 networks (most common)
                (".".join(ip_parts[:3] + ["255"]), "/24"),
                # /16 networks  
                (".".join(ip_parts[:2] + ["255", "255"]), "/16"),
                # /23 networks (common in corporate environments)
                (".".join(ip_parts[:3] + [str((int(ip_parts[3]) | 1))]), "/23"),
            ]
            
            for addr, subnet_type in subnet_configs:
                addresses.append(addr)
            
            # Always include limited broadcast as fallback
            addresses.append("255.255.255.255")
            
        except Exception as e:
            console.print(f"[yellow]Broadcast address calculation error: {e}[/yellow]")
            addresses = ["255.255.255.255"]
        
        return addresses

    def _get_broadcast_address(self) -> str:
        """Get primary broadcast address (for backward compatibility)"""
        addresses = self._get_broadcast_addresses()
        return addresses[0] if addresses else "255.255.255.255"

    def start_message_server(self):
        """Start the TCP message server with flexible port binding"""
        if not self.running:
            return

        console.print("[cyan]Starting TCP message server with flexible port binding[/cyan]")

        # Try ports in order of preference
        for port in self.message_ports:
            try:
                console.print(f"[dim]Trying message server on port {port}...[/dim]")
                
                self.message_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.message_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.message_server.bind(("", port))
                self.message_server.listen(10)

                # Update the primary port to the successful one
                self.message_port = port

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
                        
                        # Enhanced connection diagnostics
                        self._log_peer_connection(peer_info, "joined")
                        self._record_connection_attempt("Peer Join", address[0], address[1], True)
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
            error_msg = f"Peer connection error from {address[0]}:{address[1]}: {e}"
            console.print(f"[yellow]{error_msg}[/yellow]")
            self._record_connection_attempt("Peer Connection", address[0], address[1], False, str(e))
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

    def _log_peer_connection(self, peer_info: PeerInfo, action: str):
        """Log peer connection/disconnection with enhanced diagnostics"""
        if action == "joined":
            # Calculate connection duration for display
            connection_time = time.strftime("%H:%M:%S", time.localtime(peer_info.connected_at))
            
            # Determine if it's a local or remote connection
            is_local = peer_info.ip_address.startswith(("127.", "192.168.", "10.", "172."))
            connection_type = "local" if is_local else "remote"
            
            console.print(
                f"[green]✓ {peer_info.username} ({peer_info.hostname}) joined[/green] "
                f"[dim]• {peer_info.ip_address}:{peer_info.port} • {connection_type} • {connection_time}[/dim]"
            )
            
            # Show total peer count
            total_peers = len(self.peers)
            console.print(f"[dim]  └─ {total_peers} peer{'s' if total_peers != 1 else ''} connected[/dim]")
            
        elif action == "left":
            # Calculate session duration
            duration = time.time() - peer_info.connected_at
            duration_str = f"{int(duration//60)}m {int(duration%60)}s" if duration >= 60 else f"{int(duration)}s"
            
            console.print(
                f"[yellow]○ {peer_info.username} ({peer_info.hostname}) left[/yellow] "
                f"[dim]• session: {duration_str}[/dim]"
            )
            
            # Show remaining peer count
            total_peers = len(self.peers) - 1  # -1 because we haven't removed from dict yet
            if total_peers > 0:
                console.print(f"[dim]  └─ {total_peers} peer{'s' if total_peers != 1 else ''} remaining[/dim]")

    def _disconnect_peer(self, peer_id: str):
        """Disconnect and clean up peer with enhanced logging"""
        if peer_id in self.peers:
            peer_info = self.peers[peer_id]
            self._log_peer_connection(peer_info, "left")
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

    def discover_sessions_enhanced(self) -> List[SessionInfo]:
        """Enhanced session discovery with multiple methods"""
        console.print("[cyan]🔍 Discovering sessions with enhanced methods...[/cyan]")
        
        # Re-analyze network if confidence is low
        if (self.network_config and 
            self.network_config.confidence_score < 50 and
            self.network_config.discovery_strategy != "direct_connection_only"):
            console.print("[yellow]Low network confidence, re-analyzing...[/yellow]")
            self._smart_configure_network()
        
        discovered = []
        discovery_methods = [
            ("UDP Broadcast", self._discover_via_udp_broadcast),
            ("Direct Scan", self._discover_via_direct_scan if not self.corporate_mode else lambda: []),
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
        """Enhanced UDP broadcast discovery with multiple addresses"""
        sessions = []
        
        for port in self.discovery_ports:
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
                
                # Use intelligently determined broadcast addresses
                broadcast_addresses = getattr(self, 'broadcast_addresses', self._get_broadcast_addresses())
                for broadcast_ip in broadcast_addresses:
                    try:
                        discovery_sock.sendto(request_data, (broadcast_ip, port))
                        console.print(f"[dim]Sent discovery to {broadcast_ip}:{port}[/dim]")
                    except Exception as e:
                        console.print(f"[dim]Discovery broadcast to {broadcast_ip}:{port} failed: {e}[/dim]")
                        continue
                
                # Listen for responses
                start_time = time.time()
                while time.time() - start_time < 2.0:  # Increased timeout for multiple broadcasts
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
                                created_at=response["created_at"]
                            )
                            sessions.append(session_info)
                    except socket.timeout:
                        break
                    except json.JSONDecodeError:
                        continue
                
                discovery_sock.close()
                if sessions:  # If we found sessions, don't try other ports
                    break
                
            except Exception:
                if 'discovery_sock' in locals():
                    discovery_sock.close()
                continue
        
        return sessions

    def _discover_via_direct_scan(self) -> List[SessionInfo]:
        """Direct IP scanning for local network (fallback method)"""
        sessions = []
        
        # Scan local subnet for active chat servers
        ip_base = '.'.join(self.local_ip.split('.')[:-1]) + '.'
        
        # Only scan a few IPs to avoid being too intrusive
        scan_range = [1, 100, 101, 102, 200, 254]  # Common IPs
        
        for last_octet in scan_range:
            target_ip = ip_base + str(last_octet)
            if target_ip == self.local_ip:
                continue
            
            for port in self.message_ports:
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
                                created_at=time.time()
                            )
                            sessions.append(session_info)
                except Exception:
                    continue
        
        return sessions

    def get_diagnostics(self) -> Dict[str, Any]:
        """Get network diagnostics information"""
        broadcast_addresses = self._get_broadcast_addresses()
        
        return {
            "local_ip": self.local_ip,
            "local_hostname": self.local_hostname,
            "config": {
                "discovery_ports": getattr(self, 'discovery_ports', [self.discovery_port]),
                "message_ports": getattr(self, 'message_ports', [self.message_port]),
                "corporate_mode": getattr(self, 'corporate_mode', False),
                "broadcast_addresses": broadcast_addresses,
            },
            "connection_attempts": self.connection_attempts,
            "last_error": self.last_error,
            "active_connections": len(self.peer_connections),
            "session_info": {
                "name": self.session_name,
                "is_host": self.is_host,
                "peer_count": len(self.peers)
            },
            "network_troubleshooting": {
                "recommended_actions": [
                    "Try using direct IP connection if broadcast fails",
                    "Check if firewall allows UDP broadcast traffic",
                    f"Verify network subnet matches calculated broadcast addresses: {', '.join(broadcast_addresses[:3])}"
                ]
            }
        }

    def test_network_connectivity(self) -> Dict[str, Any]:
        """Test network capabilities and provide troubleshooting info"""
        results: Dict[str, Any] = {
            "broadcast_test": {},
            "port_availability": {},
            "recommendations": []
        }
        
        # Test broadcast addresses
        broadcast_addresses = self._get_broadcast_addresses()
        for addr in broadcast_addresses:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                test_sock.settimeout(1.0)
                
                test_message = json.dumps({"type": "test", "timestamp": time.time()}).encode()
                test_sock.sendto(test_message, (addr, self.discovery_port))
                
                results["broadcast_test"][addr] = {"status": "success", "error": None}
                test_sock.close()
                
            except Exception as e:
                results["broadcast_test"][addr] = {"status": "failed", "error": str(e)}
        
        # Test port availability
        for port in self.discovery_ports:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.bind(("", port))
                test_sock.close()
                results["port_availability"][port] = {"status": "available", "protocol": "UDP"}
            except Exception as e:
                results["port_availability"][port] = {"status": "unavailable", "error": str(e)}
        
        # Generate recommendations
        failed_broadcasts = [addr for addr, result in results["broadcast_test"].items() 
                           if result["status"] == "failed"]
        
        if failed_broadcasts:
            results["recommendations"].append(
                f"Broadcast failing to {len(failed_broadcasts)} addresses - network may block broadcast traffic"
            )
            results["recommendations"].append(
                "Consider using direct IP connection instead of discovery"
            )
        
        unavailable_ports = [port for port, result in results["port_availability"].items() 
                           if result["status"] == "unavailable"]
        
        if unavailable_ports:
            results["recommendations"].append(
                f"Ports {unavailable_ports} unavailable - may conflict with other services"
            )
        
        return results

    def discover_sessions(self) -> List[Dict[str, Any]]:
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
            
            # Use intelligently determined broadcast addresses
            broadcast_addresses = getattr(self, 'broadcast_addresses', self._get_broadcast_addresses())
            
            # Send to each broadcast address
            for broadcast_ip in broadcast_addresses:
                try:
                    discovery_sock.sendto(request_data, (broadcast_ip, self.discovery_port))
                    console.print(
                        f"  [dim]Sent discovery request to {broadcast_ip}:{self.discovery_port}[/dim]"
                    )
                except Exception as e:
                    console.print(f"  [yellow]Failed to send to {broadcast_ip}: {e}[/yellow]")
                    continue

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

    def connect_to_session_direct(self, host_ip: str, port: int, session_name: Optional[str] = None) -> bool:
        """Connect directly to a session using IP and port (bypasses discovery)"""
        if not session_name:
            session_name = f"direct_{host_ip}_{port}"
        
        console.print(
            f"[cyan]Connecting directly to {host_ip}:{port}[/cyan]"
        )

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10.0)  # Only for initial connection
            client_socket.connect((host_ip, port))

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

                # Enhanced connection success diagnostics
                connection_time = time.strftime("%H:%M:%S", time.localtime())
                console.print(
                    f"[green]✓ Connected to session via direct connection[/green] "
                    f"[dim]• {host_ip}:{port} • {connection_time}[/dim]"
                )
                
                self._record_connection_attempt("Direct Connect", host_ip, port, True)
                return True
            else:
                console.print("[red]Connection rejected by host[/red]")
                client_socket.close()
                return False

        except Exception as e:
            error_msg = f"Failed to connect directly: {e}"
            console.print(f"[red]{error_msg}[/red]")
            self._record_connection_attempt("Direct Connect", host_ip, port, False, str(e))
            return False

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

                # Enhanced connection success diagnostics
                connection_time = time.strftime("%H:%M:%S", time.localtime())
                console.print(
                    f"[green]✓ Connected to {session_name}[/green] "
                    f"[dim]• {session_info.host_ip}:{session_info.port} • {connection_time}[/dim]"
                )
                console.print(f"[dim]  └─ Host: {session_info.host} • Users: {session_info.user_count}[/dim]")
                
                self._record_connection_attempt("Client Connect", session_info.host_ip, session_info.port, True)
                return True
            else:
                console.print("[red]Connection rejected by host[/red]")
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
            self.peers[peer_id]
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
