#!/usr/bin/env python3
"""
Network Debugger for Pear Chat
Diagnoses connectivity issues and tests different network configurations
"""

import socket
import time
import json
import subprocess
import platform
from typing import List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()


@dataclass
class NetworkDiagnostic:
    test_name: str
    status: str  # "pass", "fail", "warning"
    message: str
    details: Optional[Dict] = None


class NetworkDebugger:
    """Comprehensive network debugging tool for Pear Chat"""
    
    def __init__(self):
        self.diagnostics: List[NetworkDiagnostic] = []
        self.local_ip = self._get_local_ip()
        self.external_ip = self._get_external_ip()
        self.hostname = socket.gethostname()
        
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def _get_external_ip(self) -> Optional[str]:
        """Get external IP address"""
        try:
            import urllib.request
            with urllib.request.urlopen('https://api.ipify.org', timeout=5) as response:
                return response.read().decode('utf-8').strip()
        except Exception:
            return None
    
    def run_full_diagnostics(self) -> List[NetworkDiagnostic]:
        """Run comprehensive network diagnostics"""
        console.print("[bold cyan]🔍 Running Network Diagnostics for Pear Chat[/bold cyan]\n")
        
        # Clear previous diagnostics
        self.diagnostics.clear()
        
        with Progress() as progress:
            task = progress.add_task("Running diagnostics...", total=12)
            
            # Basic network info
            progress.update(task, advance=1)
            self._test_basic_network_info()
            
            # Port availability tests
            progress.update(task, advance=1)
            self._test_port_availability()
            
            # UDP broadcast tests
            progress.update(task, advance=1)
            self._test_udp_broadcast()
            
            # TCP connectivity tests
            progress.update(task, advance=1)
            self._test_tcp_connectivity()
            
            # Firewall detection
            progress.update(task, advance=1)
            self._test_firewall_detection()
            
            # Network type detection
            progress.update(task, advance=1)
            self._test_network_type()
            
            # NAT detection
            progress.update(task, advance=1)
            self._test_nat_detection()
            
            # DNS resolution
            progress.update(task, advance=1)
            self._test_dns_resolution()
            
            # Network interfaces
            progress.update(task, advance=1)
            self._test_network_interfaces()
            
            # Routing table
            progress.update(task, advance=1)
            self._test_routing_info()
            
            # Proxy detection
            progress.update(task, advance=1)
            self._test_proxy_detection()
            
            # Alternative port scanning
            progress.update(task, advance=1)
            self._test_alternative_ports()
        
        self._display_results()
        return self.diagnostics
    
    def _test_basic_network_info(self):
        """Test basic network information"""
        details = {
            "hostname": self.hostname,
            "local_ip": self.local_ip,
            "external_ip": self.external_ip,
            "platform": platform.system()
        }
        
        if self.local_ip != "127.0.0.1":
            self.diagnostics.append(NetworkDiagnostic(
                "Basic Network Info",
                "pass",
                f"Network interface available: {self.local_ip}",
                details
            ))
        else:
            self.diagnostics.append(NetworkDiagnostic(
                "Basic Network Info",
                "fail",
                "No network interface detected",
                details
            ))
    
    def _test_port_availability(self):
        """Test if required ports are available"""
        ports_to_test = [8888, 8889, 9999, 7777, 6666]  # Include alternatives
        available_ports = []
        unavailable_ports = []
        
        for port in ports_to_test:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    available_ports.append(port)
            except OSError:
                unavailable_ports.append(port)
        
        if 8888 in available_ports and 8889 in available_ports:
            status = "pass"
            message = f"Default ports available: {available_ports[:2]}"
        elif len(available_ports) >= 2:
            status = "warning"
            message = f"Default ports busy, alternatives available: {available_ports}"
        else:
            status = "fail"
            message = f"Most ports unavailable. Available: {available_ports}"
        
        self.diagnostics.append(NetworkDiagnostic(
            "Port Availability",
            status,
            message,
            {"available": available_ports, "unavailable": unavailable_ports}
        ))
    
    def _test_udp_broadcast(self):
        """Test UDP broadcast capability"""
        try:
            # Test local UDP broadcast
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(1.0)
                
                # Try to send a broadcast message
                test_message = json.dumps({"type": "test_broadcast", "timestamp": time.time()})
                broadcast_addr = self._get_broadcast_address()
                
                s.sendto(test_message.encode(), (broadcast_addr, 8888))
                
                # Check if we can bind to the broadcast port
                try:
                    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(('', 8888))
                    listener.close()
                    
                    self.diagnostics.append(NetworkDiagnostic(
                        "UDP Broadcast",
                        "pass",
                        f"UDP broadcast working to {broadcast_addr}",
                        {"broadcast_address": broadcast_addr}
                    ))
                except OSError:
                    self.diagnostics.append(NetworkDiagnostic(
                        "UDP Broadcast",
                        "warning",
                        "UDP broadcast send works, but port binding may be restricted",
                        {"broadcast_address": broadcast_addr}
                    ))
                    
        except Exception as e:
            self.diagnostics.append(NetworkDiagnostic(
                "UDP Broadcast",
                "fail",
                f"UDP broadcast failed: {str(e)}",
                {"error": str(e)}
            ))
    
    def _test_tcp_connectivity(self):
        """Test TCP connectivity"""
        try:
            # Test TCP server capability
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('', 8889))
            server.listen(1)
            
            # Test TCP client capability
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(1.0)
            
            # Try to connect to ourselves
            try:
                client.connect((self.local_ip, 8889))
                client.close()
                server.close()
                
                self.diagnostics.append(NetworkDiagnostic(
                    "TCP Connectivity",
                    "pass",
                    "TCP server and client functionality working",
                    {"local_ip": self.local_ip, "port": 8889}
                ))
            except socket.timeout:
                server.close()
                self.diagnostics.append(NetworkDiagnostic(
                    "TCP Connectivity",
                    "warning",
                    "TCP server can bind but localhost connection blocked",
                    {"local_ip": self.local_ip, "port": 8889}
                ))
            except Exception as e:
                server.close()
                self.diagnostics.append(NetworkDiagnostic(
                    "TCP Connectivity",
                    "fail",
                    f"TCP connectivity issue: {str(e)}",
                    {"error": str(e)}
                ))
                
        except Exception as e:
            self.diagnostics.append(NetworkDiagnostic(
                "TCP Connectivity",
                "fail",
                f"Cannot bind TCP server: {str(e)}",
                {"error": str(e)}
            ))
    
    def _test_firewall_detection(self):
        """Detect firewall restrictions"""
        # This is a basic detection - real firewall detection is complex
        blocked_indicators = 0
        
        # Check if we can connect to external services
        external_services = [
            ("8.8.8.8", 53),  # DNS
            ("1.1.1.1", 53),  # Cloudflare DNS
        ]
        
        for host, port in external_services:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect((host, port))
            except Exception:
                blocked_indicators += 1
        
        if blocked_indicators == 0:
            status = "pass"
            message = "Basic outbound connectivity working"
        elif blocked_indicators < len(external_services):
            status = "warning"
            message = "Some outbound connections blocked - possible firewall"
        else:
            status = "fail"
            message = "Most outbound connections blocked - restrictive firewall"
        
        self.diagnostics.append(NetworkDiagnostic(
            "Firewall Detection",
            status,
            message,
            {"blocked_services": blocked_indicators, "total_tested": len(external_services)}
        ))
    
    def _test_network_type(self):
        """Detect type of network (corporate, home, etc.)"""
        indicators = {
            "corporate": 0,
            "home": 0,
            "public": 0
        }
        
        # Check IP ranges
        ip_parts = self.local_ip.split('.')
        if ip_parts[0] == '10':
            indicators["corporate"] += 2
        elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
            indicators["corporate"] += 2
        elif ip_parts[0] == '192' and ip_parts[1] == '168':
            indicators["home"] += 2
        
        # Check hostname patterns
        if 'corp' in self.hostname.lower() or 'company' in self.hostname.lower():
            indicators["corporate"] += 1
        
        # Check if we're behind NAT
        if self.external_ip and self.external_ip != self.local_ip:
            indicators["home"] += 1
        
        network_type = max(indicators.items(), key=lambda x: x[1])[0]
        confidence = max(indicators.values())
        
        self.diagnostics.append(NetworkDiagnostic(
            "Network Type Detection",
            "pass",
            f"Detected network type: {network_type} (confidence: {confidence})",
            {"type": network_type, "confidence": confidence, "indicators": indicators}
        ))
    
    def _test_nat_detection(self):
        """Detect NAT/proxy configuration"""
        if self.external_ip and self.local_ip != self.external_ip:
            status = "warning"
            message = f"Behind NAT: Local {self.local_ip} != External {self.external_ip}"
        elif not self.external_ip:
            status = "warning"
            message = "Cannot determine external IP - possible proxy/firewall"
        else:
            status = "pass"
            message = "Direct internet connection detected"
        
        self.diagnostics.append(NetworkDiagnostic(
            "NAT Detection",
            status,
            message,
            {"local_ip": self.local_ip, "external_ip": self.external_ip}
        ))
    
    def _test_dns_resolution(self):
        """Test DNS resolution"""
        try:
            socket.gethostbyname('google.com')
            self.diagnostics.append(NetworkDiagnostic(
                "DNS Resolution",
                "pass",
                "DNS resolution working",
                {}
            ))
        except Exception as e:
            self.diagnostics.append(NetworkDiagnostic(
                "DNS Resolution",
                "fail",
                f"DNS resolution failed: {str(e)}",
                {"error": str(e)}
            ))
    
    def _test_network_interfaces(self):
        """Test network interface information"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            
            if result.returncode == 0:
                interface_count = result.stdout.count('inet') if 'inet' in result.stdout else 0
                self.diagnostics.append(NetworkDiagnostic(
                    "Network Interfaces",
                    "pass",
                    f"Network interfaces accessible ({interface_count} inet addresses found)",
                    {"interface_count": interface_count}
                ))
            else:
                self.diagnostics.append(NetworkDiagnostic(
                    "Network Interfaces",
                    "warning",
                    "Cannot access network interface information",
                    {}
                ))
        except Exception as e:
            self.diagnostics.append(NetworkDiagnostic(
                "Network Interfaces",
                "warning",
                f"Interface detection failed: {str(e)}",
                {"error": str(e)}
            ))
    
    def _test_routing_info(self):
        """Test routing information"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            else:
                result = subprocess.run(['route', '-n'], capture_output=True, text=True)
            
            if result.returncode == 0:
                has_default_route = 'default' in result.stdout or '0.0.0.0' in result.stdout
                status = "pass" if has_default_route else "warning"
                message = "Default route found" if has_default_route else "No default route detected"
                
                self.diagnostics.append(NetworkDiagnostic(
                    "Routing Information",
                    status,
                    message,
                    {"has_default_route": has_default_route}
                ))
            else:
                self.diagnostics.append(NetworkDiagnostic(
                    "Routing Information",
                    "warning",
                    "Cannot access routing information",
                    {}
                ))
        except Exception as e:
            self.diagnostics.append(NetworkDiagnostic(
                "Routing Information",
                "warning",
                f"Routing detection failed: {str(e)}",
                {"error": str(e)}
            ))
    
    def _test_proxy_detection(self):
        """Detect proxy configuration"""
        import os
        
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        proxy_detected = any(os.environ.get(var) for var in proxy_vars)
        
        if proxy_detected:
            proxy_info = {var: os.environ.get(var) for var in proxy_vars if os.environ.get(var)}
            self.diagnostics.append(NetworkDiagnostic(
                "Proxy Detection",
                "warning",
                f"Proxy configuration detected: {list(proxy_info.keys())}",
                {"proxy_vars": proxy_info}
            ))
        else:
            self.diagnostics.append(NetworkDiagnostic(
                "Proxy Detection",
                "pass",
                "No proxy environment variables detected",
                {}
            ))
    
    def _test_alternative_ports(self):
        """Test alternative ports that might work better"""
        alternative_ports = [
            80,    # HTTP
            443,   # HTTPS
            53,    # DNS
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            110,   # POP3
            143,   # IMAP
            993,   # IMAPS
            995,   # POP3S
            1234,  # Common alt
            3000,  # Dev server
            5000,  # Dev server
            9000,  # Alt HTTP
        ]
        
        open_ports = []
        for port in alternative_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex(('127.0.0.1', port))
                    if result != 0:  # Port is not in use (good for us)
                        try:
                            s.bind(('', port))
                            open_ports.append(port)
                        except OSError:
                            pass
            except Exception:
                pass
        
        if len(open_ports) > 0:
            status = "pass"
            message = f"Alternative ports available: {open_ports[:5]}"
        else:
            status = "warning"
            message = "No alternative ports found"
        
        self.diagnostics.append(NetworkDiagnostic(
            "Alternative Ports",
            status,
            message,
            {"available_ports": open_ports}
        ))
    
    def _get_broadcast_address(self) -> str:
        """Calculate broadcast address for current network"""
        try:
            ip_parts = self.local_ip.split(".")
            ip_parts[-1] = "255"
            return ".".join(ip_parts)
        except:
            return "255.255.255.255"
    
    def _display_results(self):
        """Display diagnostic results in a formatted table"""
        console.print("\n[bold cyan]🔍 Network Diagnostic Results[/bold cyan]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Test", style="cyan", width=20)
        table.add_column("Status", width=8)
        table.add_column("Message", width=50)
        
        for diagnostic in self.diagnostics:
            if diagnostic.status == "pass":
                status_icon = "[green]✓ PASS[/green]"
            elif diagnostic.status == "warning":
                status_icon = "[yellow]⚠ WARN[/yellow]"
            else:
                status_icon = "[red]✗ FAIL[/red]"
            
            table.add_row(diagnostic.test_name, status_icon, diagnostic.message)
        
        console.print(table)
        
        # Summary
        pass_count = sum(1 for d in self.diagnostics if d.status == "pass")
        warn_count = sum(1 for d in self.diagnostics if d.status == "warning")
        fail_count = sum(1 for d in self.diagnostics if d.status == "fail")
        
        summary = f"Summary: {pass_count} passed, {warn_count} warnings, {fail_count} failed"
        
        if fail_count > 0:
            console.print(f"\n[red]{summary}[/red]")
        elif warn_count > 0:
            console.print(f"\n[yellow]{summary}[/yellow]")
        else:
            console.print(f"\n[green]{summary}[/green]")
    
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on diagnostic results"""
        recommendations = []
        
        # Check for common issues
        udp_failed = any(d.test_name == "UDP Broadcast" and d.status == "fail" 
                        for d in self.diagnostics)
        tcp_failed = any(d.test_name == "TCP Connectivity" and d.status == "fail" 
                        for d in self.diagnostics)
        ports_busy = any(d.test_name == "Port Availability" and d.status != "pass" 
                        for d in self.diagnostics)
        behind_nat = any(d.test_name == "NAT Detection" and d.status == "warning" 
                        for d in self.diagnostics)
        corporate_network = any(d.test_name == "Network Type Detection" and 
                              d.details and d.details.get("type") == "corporate" 
                              for d in self.diagnostics)
        
        if udp_failed:
            recommendations.append("🔧 UDP broadcast is blocked - consider using TCP-only discovery")
            recommendations.append("🔧 Implement WebSocket or HTTP-based discovery service")
        
        if tcp_failed:
            recommendations.append("🔧 TCP connectivity issues - check firewall settings")
            recommendations.append("🔧 Consider using alternative ports (80, 443, 3000)")
        
        if ports_busy:
            recommendations.append("🔧 Default ports are busy - implement dynamic port allocation")
            recommendations.append("🔧 Use available alternative ports from diagnostic results")
        
        if behind_nat:
            recommendations.append("🔧 Behind NAT - implement STUN/TURN server for NAT traversal")
            recommendations.append("🔧 Consider using a relay server for initial connections")
        
        if corporate_network:
            recommendations.append("🔧 Corporate network detected - implement HTTP/WebSocket fallback")
            recommendations.append("🔧 Add support for proxy configuration")
            recommendations.append("🔧 Consider using cloud relay service for corporate environments")
        
        if not recommendations:
            recommendations.append("✅ Network appears healthy - issues may be intermittent")
            recommendations.append("🔧 Consider implementing connection retry logic")
        
        return recommendations


def main():
    """Main function to run network diagnostics"""
    debugger = NetworkDebugger()
    
    # Run diagnostics
    results = debugger.run_full_diagnostics()
    
    # Generate and display recommendations
    recommendations = debugger.generate_recommendations()
    
    if recommendations:
        console.print("\n[bold yellow]💡 Recommendations[/bold yellow]\n")
        for rec in recommendations:
            console.print(f"  {rec}")
    
    # Export results
    console.print("\n[dim]Results exported to: network_diagnostic_results.json[/dim]")
    with open("network_diagnostic_results.json", "w") as f:
        json.dump([{
            "test_name": d.test_name,
            "status": d.status,
            "message": d.message,
            "details": d.details
        } for d in results], f, indent=2)


if __name__ == "__main__":
    main()