"""
Network Layer - P2P networking components
Handles discovery, connections, and message routing
"""

import socket
import threading
import time
import json
from typing import List, Dict, Optional
from dataclasses import dataclass
import uuid


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
        
        # Mock data for testing
        self._mock_sessions = []
        self._mock_peers = []
        
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
    
    def start_discovery_service(self):
        """Start the discovery service for broadcasting session availability"""
        print(f"[MOCK] Starting discovery service on port {self.discovery_port}")
        self.running = True
        
        # In a real implementation, this would start a UDP server
        # that broadcasts session information and responds to discovery requests
        discovery_thread = threading.Thread(target=self._mock_discovery_service)
        discovery_thread.daemon = True
        discovery_thread.start()
    
    def _mock_discovery_service(self):
        """Mock discovery service that simulates network broadcasting"""
        while self.running:
            # Simulate discovery broadcasts
            if self.session_name:
                print(f"[MOCK] Broadcasting session: {self.session_name}")
            time.sleep(5)  # Broadcast every 5 seconds
    
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
        """Discover active chat sessions on the network"""
        print("[MOCK] Discovering sessions on network...")
        
        # Mock sessions for testing
        mock_sessions = [
            SessionInfo(
                name="dev_chat",
                host="alice-laptop",
                host_ip="192.168.1.100",
                port=8889,
                user_count=2,
                created_at=time.time() - 300
            ),
            SessionInfo(
                name="team_standup",
                host="bob-desktop",
                host_ip="192.168.1.101", 
                port=8889,
                user_count=4,
                created_at=time.time() - 600
            )
        ]
        
        # Convert to dict format expected by CLI
        sessions = []
        for session in mock_sessions:
            sessions.append({
                'name': session.name,
                'host': session.host,
                'host_ip': session.host_ip,
                'port': session.port,
                'user_count': session.user_count
            })
        
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
        print("[MOCK] Stopping network services...")
        self.running = False
        self.peers.clear()
        self.session_name = None 