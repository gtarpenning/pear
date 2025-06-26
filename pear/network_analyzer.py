"""
Network Analyzer - Intelligent network configuration detection
Analyzes current network setup to optimize P2P discovery
"""

import socket
import subprocess
import platform
import ipaddress
import struct
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from rich.console import Console

console = Console()


@dataclass
class NetworkInterface:
    """Information about a network interface"""
    name: str
    ip_address: str
    netmask: str
    broadcast: Optional[str]
    gateway: Optional[str]
    is_active: bool
    is_wireless: bool


@dataclass
class NetworkConfig:
    """Optimized network configuration for P2P"""
    primary_interface: NetworkInterface
    broadcast_addresses: List[str]
    discovery_strategy: str
    port_recommendations: Dict[str, List[int]]
    confidence_score: int
    diagnostics: Dict[str, Any]


class NetworkAnalyzer:
    """Analyzes network configuration and provides optimized P2P settings"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.interfaces: List[NetworkInterface] = []
        self.routing_table: List[Dict[str, Any]] = []
        
    def analyze_network(self) -> NetworkConfig:
        """Perform comprehensive network analysis"""
        console.print("[cyan]🔍 Analyzing network configuration...[/cyan]")
        
        # Step 1: Discover network interfaces
        self.interfaces = self._discover_interfaces()
        
        # Step 2: Analyze routing table
        self.routing_table = self._get_routing_table()
        
        # Step 3: Select primary interface
        primary_interface = self._select_primary_interface()
        
        # Step 4: Calculate optimal broadcast addresses
        broadcast_addresses = self._calculate_broadcast_addresses(primary_interface)
        
        # Step 5: Test connectivity
        connectivity_results = self._test_connectivity(broadcast_addresses)
        
        # Step 6: Determine strategy
        strategy = self._determine_strategy(connectivity_results)
        
        # Step 7: Recommend ports
        port_recommendations = self._recommend_ports()
        
        # Step 8: Calculate confidence score
        confidence = self._calculate_confidence(primary_interface, connectivity_results)
        
        config = NetworkConfig(
            primary_interface=primary_interface,
            broadcast_addresses=broadcast_addresses,
            discovery_strategy=strategy,
            port_recommendations=port_recommendations,
            confidence_score=confidence,
            diagnostics={
                "total_interfaces": len(self.interfaces),
                "active_interfaces": len([i for i in self.interfaces if i.is_active]),
                "connectivity_results": connectivity_results,
                "system": self.system
            }
        )
        
        self._print_analysis_summary(config)
        return config
    
    def _discover_interfaces(self) -> List[NetworkInterface]:
        """Discover all network interfaces with detailed information"""
        interfaces = []
        
        try:
            if self.system == "darwin":  # macOS
                interfaces = self._discover_interfaces_macos()
            elif self.system == "linux":
                interfaces = self._discover_interfaces_linux()
            else:  # Windows or fallback
                interfaces = self._discover_interfaces_fallback()
                
        except Exception as e:
            console.print(f"[yellow]Interface discovery error: {e}[/yellow]")
            interfaces = self._discover_interfaces_fallback()
        
        # Filter out loopback and non-IP interfaces
        active_interfaces = []
        for iface in interfaces:
            if (iface.ip_address and 
                not iface.ip_address.startswith("127.") and 
                not iface.ip_address.startswith("169.254.")):  # Skip link-local
                active_interfaces.append(iface)
                
        return active_interfaces
    
    def _discover_interfaces_macos(self) -> List[NetworkInterface]:
        """Discover interfaces on macOS using ifconfig"""
        interfaces = []
        
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return self._discover_interfaces_fallback()
                
            current_interface = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # New interface
                if line and not line.startswith(' ') and ':' in line:
                    if current_interface:
                        interfaces.append(current_interface)
                    
                    interface_name = line.split(':')[0]
                    current_interface = NetworkInterface(
                        name=interface_name,
                        ip_address="",
                        netmask="",
                        broadcast=None,
                        gateway=None,
                        is_active=False,
                        is_wireless="wl" in interface_name.lower() or "wifi" in interface_name.lower()
                    )
                
                elif current_interface and line.startswith('inet '):
                    # Parse IP address and netmask
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            current_interface.ip_address = parts[i + 1]
                        elif part == 'netmask' and i + 1 < len(parts):
                            # Convert hex netmask to dotted decimal
                            netmask_hex = parts[i + 1]
                            if netmask_hex.startswith('0x'):
                                netmask_int = int(netmask_hex, 16)
                                current_interface.netmask = socket.inet_ntoa(struct.pack('!I', netmask_int))
                        elif part == 'broadcast' and i + 1 < len(parts):
                            current_interface.broadcast = parts[i + 1]
                
                elif current_interface and 'status: active' in line:
                    current_interface.is_active = True
            
            # Add the last interface
            if current_interface:
                interfaces.append(current_interface)
                
        except Exception as e:
            console.print(f"[yellow]macOS interface discovery failed: {e}[/yellow]")
            return self._discover_interfaces_fallback()
        
        return interfaces
    
    def _discover_interfaces_linux(self) -> List[NetworkInterface]:
        """Discover interfaces on Linux"""
        
        try:
            # Use ip command if available
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return self._parse_ip_addr_output(result.stdout)
        except:
            pass
        
        # Fallback to ifconfig
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return self._parse_ifconfig_output(result.stdout)
        except:
            pass
        
        return self._discover_interfaces_fallback()
    
    def _discover_interfaces_fallback(self) -> List[NetworkInterface]:
        """Fallback interface discovery using Python socket"""
        interfaces = []
        
        try:
            # Get local IP by connecting to external address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                
            # Create a basic interface entry
            interface = NetworkInterface(
                name="primary",
                ip_address=local_ip,
                netmask="255.255.255.0",  # Common default
                broadcast=None,
                gateway=None,
                is_active=True,
                is_wireless=False
            )
            interfaces.append(interface)
            
        except Exception as e:
            console.print(f"[red]Fallback interface discovery failed: {e}[/red]")
        
        return interfaces
    
    def _parse_ip_addr_output(self, output: str) -> List[NetworkInterface]:
        """Parse 'ip addr show' output"""
        interfaces: List[NetworkInterface] = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line and line[0].isdigit() and ':' in line:
                # New interface line
                if current_interface:
                    interfaces.append(current_interface)
                
                parts = line.split()
                interface_name = parts[1].rstrip(':')
                is_active = 'UP' in line
                
                current_interface = NetworkInterface(
                    name=interface_name,
                    ip_address="",
                    netmask="",
                    broadcast=None,
                    gateway=None,
                    is_active=is_active,
                    is_wireless="wl" in interface_name or "wifi" in interface_name
                )
            
            elif current_interface and line.startswith('inet '):
                # Parse IP address
                parts = line.split()
                if len(parts) >= 2:
                    ip_with_prefix = parts[1]
                    if '/' in ip_with_prefix:
                        ip_addr, prefix_len = ip_with_prefix.split('/')
                        current_interface.ip_address = ip_addr
                        # Convert CIDR to netmask
                        current_interface.netmask = str(ipaddress.IPv4Network(f'0.0.0.0/{prefix_len}', strict=False).netmask)
                
                # Look for broadcast address
                if 'brd' in parts:
                    brd_index = parts.index('brd')
                    if brd_index + 1 < len(parts):
                        current_interface.broadcast = parts[brd_index + 1]
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_ifconfig_output(self, output: str) -> List[NetworkInterface]:
        """Parse ifconfig output for Linux"""
        interfaces: List[NetworkInterface] = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line and not line.startswith(' ') and ':' in line:
                if current_interface:
                    interfaces.append(current_interface)
                
                interface_name = line.split(':')[0]
                current_interface = NetworkInterface(
                    name=interface_name,
                    ip_address="",
                    netmask="",
                    broadcast=None,
                    gateway=None,
                    is_active=False,
                    is_wireless="wl" in interface_name or "wifi" in interface_name
                )
            
            elif current_interface and 'inet ' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'inet' and i + 1 < len(parts):
                        current_interface.ip_address = parts[i + 1]
                    elif part == 'netmask' and i + 1 < len(parts):
                        current_interface.netmask = parts[i + 1]
                    elif part == 'broadcast' and i + 1 < len(parts):
                        current_interface.broadcast = parts[i + 1]
            
            elif current_interface and 'UP' in line:
                current_interface.is_active = True
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _get_routing_table(self) -> List[Dict[str, Any]]:
        """Get system routing table"""
        routes = []
        
        try:
            if self.system == "darwin":
                result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                routes = self._parse_netstat_routes(result.stdout)
            elif self.system == "linux":
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
                routes = self._parse_ip_routes(result.stdout)
        except Exception as e:
            console.print(f"[yellow]Routing table analysis failed: {e}[/yellow]")
        
        return routes
    
    def _parse_netstat_routes(self, output: str) -> List[Dict[str, Any]]:
        """Parse netstat -rn output"""
        routes = []
        
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 4 and parts[0] not in ['Destination', 'Internet:', 'Internet6:']:
                try:
                    route = {
                        'destination': parts[0],
                        'gateway': parts[1],
                        'flags': parts[2] if len(parts) > 2 else '',
                        'interface': parts[-1] if parts else ''
                    }
                    routes.append(route)
                except:
                    continue
        
        return routes
    
    def _parse_ip_routes(self, output: str) -> List[Dict[str, Any]]:
        """Parse ip route output"""
        routes = []
        
        for line in output.split('\n'):
            if line.strip():
                route = {
                    'destination': '',
                    'gateway': '',
                    'interface': '',
                    'raw': line
                }
                
                parts = line.split()
                if 'via' in parts:
                    via_index = parts.index('via')
                    if via_index + 1 < len(parts):
                        route['gateway'] = parts[via_index + 1]
                
                if 'dev' in parts:
                    dev_index = parts.index('dev')
                    if dev_index + 1 < len(parts):
                        route['interface'] = parts[dev_index + 1]
                
                routes.append(route)
        
        return routes
    
    def _select_primary_interface(self) -> NetworkInterface:
        """Select the best interface for P2P networking"""
        if not self.interfaces:
            # Create a minimal fallback interface
            return NetworkInterface(
                name="fallback",
                ip_address="127.0.0.1",
                netmask="255.255.255.0",
                broadcast=None,
                gateway=None,
                is_active=False,
                is_wireless=False
            )
        
        # Score interfaces based on various criteria
        scored_interfaces = []
        
        for interface in self.interfaces:
            score = 0
            
            # Prefer active interfaces
            if interface.is_active:
                score += 50
            
            # Prefer interfaces with broadcast addresses
            if interface.broadcast:
                score += 30
            
            # Prefer wired over wireless for stability
            if not interface.is_wireless:
                score += 20
            
            # Prefer private network ranges
            if interface.ip_address:
                try:
                    ip = ipaddress.IPv4Address(interface.ip_address)
                    if ip.is_private:
                        score += 25
                except:
                    pass
            
            # Prefer interfaces with proper netmask
            if interface.netmask and interface.netmask != "255.255.255.255":
                score += 15
            
            scored_interfaces.append((score, interface))
        
        # Sort by score and return the best
        scored_interfaces.sort(key=lambda x: x[0], reverse=True)
        
        selected = scored_interfaces[0][1]
        console.print(f"[green]Selected primary interface: {selected.name} ({selected.ip_address})[/green]")
        
        return selected
    
    def _calculate_broadcast_addresses(self, interface: NetworkInterface) -> List[str]:
        """Calculate proper broadcast addresses based on interface configuration"""
        addresses = []
        
        if not interface.ip_address or not interface.netmask:
            return ["255.255.255.255"]
        
        try:
            # If interface provides broadcast address, use it first
            if interface.broadcast:
                addresses.append(interface.broadcast)
                console.print(f"[green]Using system broadcast: {interface.broadcast}[/green]")
            
            # Calculate network broadcast based on IP and netmask
            network = ipaddress.IPv4Network(f"{interface.ip_address}/{interface.netmask}", strict=False)
            calculated_broadcast = str(network.broadcast_address)
            
            if calculated_broadcast not in addresses:
                addresses.append(calculated_broadcast)
                console.print(f"[green]Calculated broadcast: {calculated_broadcast} (/{network.prefixlen})[/green]")
            
            # Add limited broadcast as fallback
            if "255.255.255.255" not in addresses:
                addresses.append("255.255.255.255")
            
        except Exception as e:
            console.print(f"[yellow]Broadcast calculation error: {e}[/yellow]")
            addresses = ["255.255.255.255"]
        
        return addresses
    
    def _test_connectivity(self, broadcast_addresses: List[str]) -> Dict[str, Any]:
        """Test broadcast connectivity"""
        results: Dict[str, Any] = {
            "broadcast_reachable": [],
            "broadcast_failed": [],
            "port_availability": {},
            "routing_issues": []
        }
        
        # Test each broadcast address
        for addr in broadcast_addresses:
            try:
                # Create a test socket
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                test_sock.settimeout(1.0)
                
                # Try to send a test packet
                test_data = b"test"
                test_sock.sendto(test_data, (addr, 9999))  # Use high port unlikely to be used
                
                results["broadcast_reachable"].append(addr)
                console.print(f"[green]✓ Broadcast reachable: {addr}[/green]")
                test_sock.close()
                
            except Exception as e:
                results["broadcast_failed"].append({"address": addr, "error": str(e)})
                console.print(f"[yellow]✗ Broadcast failed: {addr} - {e}[/yellow]")
                try:
                    test_sock.close()
                except:
                    pass
        
        # Test port availability
        test_ports = [8888, 8889, 3000, 5000, 9000]
        for port in test_ports:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.bind(("", port))
                test_sock.close()
                results["port_availability"][port] = "available"
            except Exception as e:
                results["port_availability"][port] = f"unavailable: {str(e)}"
        
        return results
    
    def _determine_strategy(self, connectivity_results: Dict[str, Any]) -> str:
        """Determine the best discovery strategy based on test results"""
        if connectivity_results["broadcast_reachable"]:
            return "broadcast_discovery"
        elif len(connectivity_results["broadcast_failed"]) > 0:
            return "direct_connection_only"
        else:
            return "hybrid_approach"
    
    def _recommend_ports(self) -> Dict[str, List[int]]:
        """Recommend optimal ports based on availability"""
        return {
            "discovery": [8888, 3000, 5000, 9000, 8080],
            "messaging": [8889, 3001, 5001, 9001, 8081]
        }
    
    def _calculate_confidence(self, interface: NetworkInterface, connectivity: Dict[str, Any]) -> int:
        """Calculate confidence score for the network configuration"""
        confidence = 0
        
        # Interface quality
        if interface.is_active:
            confidence += 30
        if interface.broadcast:
            confidence += 20
        if interface.netmask and interface.netmask != "255.255.255.255":
            confidence += 15
        
        # Connectivity results
        if connectivity["broadcast_reachable"]:
            confidence += 30
        else:
            confidence -= 20
        
        # Port availability
        available_ports = sum(1 for status in connectivity["port_availability"].values() 
                            if status == "available")
        confidence += min(available_ports * 5, 25)
        
        return max(0, min(100, confidence))
    
    def _print_analysis_summary(self, config: NetworkConfig):
        """Print a summary of the network analysis"""
        console.print("\n[bold cyan]Network Analysis Complete[/bold cyan]")
        console.print(f"[cyan]Primary Interface:[/cyan] {config.primary_interface.name}")
        console.print(f"[cyan]IP Address:[/cyan] {config.primary_interface.ip_address}")
        console.print(f"[cyan]Netmask:[/cyan] {config.primary_interface.netmask}")
        
        if config.primary_interface.broadcast:
            console.print(f"[cyan]System Broadcast:[/cyan] {config.primary_interface.broadcast}")
        
        console.print(f"[cyan]Strategy:[/cyan] {config.discovery_strategy}")
        console.print(f"[cyan]Confidence:[/cyan] {config.confidence_score}%")
        
        if config.confidence_score < 50:
            console.print("[yellow]⚠ Low confidence - recommend using direct connections[/yellow]")
        
        console.print() 