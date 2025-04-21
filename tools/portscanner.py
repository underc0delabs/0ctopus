import socket
import requests
from datetime import datetime
from config import HOST, URL_BASE

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

SERVICES = {
    21:  "ftp",
    22:  "ssh",
    23:  "telnet",
    25:  "smtp",
    53:  "dns",
    80:  "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1723:"pptp",
    3306:"mysql",
    3389:"rdp",
    5900:"vnc",
    8080:"http-proxy"
}

def grab_banner(host: str, port: int, timeout: float = 1) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        if port in (80, 8080, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            data = sock.recv(1024).decode(errors="ignore")
            server_header = next((line.split(':', 1)[1].strip() 
                                for line in data.splitlines() 
                                if line.lower().startswith("server:")), '')
            return server_header
        else:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner.splitlines()[0] if banner else ''
    except Exception:
        return ''
    finally:
        sock.close()

def scan(common: bool = True) -> list[dict]:
    ports = COMMON_PORTS if common else range(1, 65536)
    results = []

    for port in ports:
        state = 'filtered'
        service = '-'
        version = '-'
        
        try:
            with socket.socket() as sock:
                sock.settimeout(1.5)
                if sock.connect_ex((HOST, port)) == 0:
                    state = 'open'
                    service = SERVICES.get(port, '-')
                    version = grab_banner(HOST, port) or '-'
                    
                    if port in (80, 443) and version == '-':
                        try:
                            scheme = 'https' if port == 443 else 'http'
                            response = requests.head(
                                f"{scheme}://{HOST}:{port}",
                                timeout=2,
                                allow_redirects=True
                            )
                            version = response.headers.get('Server', '-')
                        except:
                            pass
        except Exception as e:
            pass
        
        results.append({
            'port': port,
            'state': state,
            'service': service,
            'version': version if version != '-' else 'No detectado'
        })
    
    return sorted(results, key=lambda x: x['port'])