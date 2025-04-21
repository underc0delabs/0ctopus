# tools/vuln_check.py

import requests
import ssl
import socket
from urllib.parse import urlparse
from config import URL_BASE

def check(url: str = URL_BASE) -> list[str]:
    """
    Chequeo rápido de:
    - Headers HTTP (Server)
    - Uso de HTTPS
    - Validez del certificado SSL
    Si no se pasa url, usa la URL_BASE de config.py.
    Devuelve lista de hallazgos/errores.
    """
    issues = []
    # Headers y HTTPS
    try:
        r = requests.get(url, timeout=3)
        server = r.headers.get('Server', 'Desconocido')
        issues.append(f"Server header: {server}")
        if not url.lower().startswith('https'):
            issues.append("Sitio NO usa HTTPS")
    except requests.RequestException:
        issues.append("Error al obtener headers HTTP")

    # SSL
    host = urlparse(url).hostname or ''
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(3)
            s.connect((host, 443))
            _ = s.getpeercert()
            issues.append("Certificado SSL válido")
    except Exception as e:
        issues.append(f"Issue SSL: {e}")
    return issues
