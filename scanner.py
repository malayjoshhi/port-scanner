import socket
import concurrent.futures
import time
from typing import List, Dict, Any, Optional

# Common port definitions for service detection
COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    27017: "MongoDB"
}

class PortScanner:
    """
    A multi-threaded TCP Port Scanner with banner grabbing capabilities.
    """
    def __init__(self, target: str, timeout: float = 1.0, grab_banner: bool = True):
        self.target = target
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.target_ip = self._resolve_target(target)

    def _resolve_target(self, target: str) -> str:
        """Resolves hostname to IP address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname: {target}")

    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """
        Scans a single TCP port and attempts to grab banner if open.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    banner = ""
                    if self.grab_banner:
                        banner = self._grab_banner(sock, port)
                    
                    return {
                        "port": port,
                        "status": "OPEN",
                        "service": service,
                        "banner": banner.strip()
                    }
        except Exception:
            pass
        return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempts to grab service banner from an open port."""
        try:
            # Send HTTP request if HTTP/HTTPS port to get response banner
            if port in [80, 8080]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 443:
                return "HTTPS (SSL/TLS encrypted)"
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner.split('\n')[0] if banner else ""
        except Exception:
            return ""

    def scan_range(self, start_port: int, end_port: int, threads: int = 50) -> List[Dict[str, Any]]:
        """
        Scans a range of ports concurrently using ThreadPoolExecutor.
        """
        open_ports = []
        ports = range(start_port, end_port + 1)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    
        return sorted(open_ports, key=lambda x: x['port'])
