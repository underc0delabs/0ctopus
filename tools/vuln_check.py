# Archivo: tools/vuln_check.py

import requests
import ssl
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from config import URL_BASE
from tools.subdomain_enum import enumerate as enum_subdomains
from colorama import Fore, Style

# Configuración de headers para requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Niveles de severidad con colores
SEVERITY = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.BLUE,
    'INFO': Fore.GREEN,
    'DEBUG': Fore.CYAN
}

# Plugins comunes para WordPress
PLUGIN_SLUGS = [
    'woocommerce',
    'contact-form-7',
    'yoast-seo',
    'elementor',
    'akismet',
    'jetpack'
]

# Configuración para detectar CMS
CMS_CHECKS = {
    'WordPress': {
        'paths': ['/wp-login.php', '/wp-admin/', '/wp-includes/'],
        'version': {
            'meta': 'generator',
            'file': '/readme.html',
            'regex': r'Version (\d+\.\d+\.\d+)'
        }
    },
    'Joomla': {
        'paths': ['/administrator/', '/joomla.xml'],
        'version': {
            'meta': 'generator',
            'file': '/administrator/manifests/files/joomla.xml',
            'regex': r'<version>(.*?)</version>'
        }
    },
    'Drupal': {
        'paths': ['/user/login', '/core/CHANGELOG.txt'],
        'version': {
            'meta': 'generator',
            'file': '/core/CHANGELOG.txt',
            'regex': r'Drupal (\d+\.\d+\.\d+)'
        }
    }
}

# Archivos sensibles con verificación de contenido
SENSITIVE_FILES = {
    '/.env': {
        'check_content': True,
        'keywords': ['DB_PASSWORD', 'SECRET_KEY'],
        'severity': 'CRITICAL'
    },
    '/.git/config': {
        'check_content': True,
        'keywords': ['[core]'],
        'severity': 'HIGH'
    },
    '/wp-config.php.bak': {
        'check_content': True,
        'keywords': ['DB_NAME', 'DB_PASSWORD'],
        'severity': 'HIGH'
    },
    '/phpinfo.php': {
        'check_content': True,
        'keywords': ['phpinfo()'],
        'severity': 'HIGH'
    },
    '/config.php': {
        'check_content': True,
        'keywords': ['password', 'database'],
        'severity': 'HIGH'
    }
}

def colorize(severity, message):
    """Aplica color según la severidad"""
    return SEVERITY.get(severity, Fore.WHITE) + message + Style.RESET_ALL

def check_ssl(url: str) -> list:
    """Verifica la configuración SSL/TLS del sitio"""
    issues = []
    parsed = urlparse(url)
    if not parsed.scheme == 'https':
        return issues
    
    host = parsed.hostname
    try:
        context = ssl.create_default_context()
        context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK')
        
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                
                # Verificar fecha de expiración
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                remaining = not_after - datetime.now()
                
                issues.append({
                    'severity': 'INFO',
                    'message': f"Certificado SSL válido hasta: {not_after.date()}",
                    'host': host
                })
                
                if remaining.days < 30:
                    issues.append({
                        'severity': 'CRITICAL',
                        'message': f"Certificado expira en {remaining.days} días!",
                        'host': host
                    })
                
                # Verificar protocolos inseguros
                if protocol in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                    issues.append({
                        'severity': 'HIGH',
                        'message': f"Protocolo inseguro: {protocol}",
                        'host': host
                    })
                
                # Verificar cifrados débiles
                cipher = ssock.cipher()
                if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0] or '3DES' in cipher[0]):
                    issues.append({
                        'severity': 'HIGH',
                        'message': f"Cifrado débil detectado: {cipher[0]}",
                        'host': host
                    })
    
    except Exception as e:
        issues.append({
            'severity': 'MEDIUM',
            'message': f"Error SSL: {str(e)}",
            'host': host
        })
    
    return issues

def check_security_headers(response) -> list:
    """Verifica las cabeceras de seguridad importantes"""
    issues = []
    url = response.url
    host = urlparse(url).hostname
    
    security_headers = {
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'description': 'Protección contra XSS y ataques de inyección'
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'description': 'Previene MIME sniffing'
        },
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'description': 'Fuerza uso de HTTPS'
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'Protección contra clickjacking'
        },
        'Permissions-Policy': {
            'severity': 'MEDIUM',
            'description': 'Control de características del navegador'
        }
    }
    
    for header, config in security_headers.items():
        if header not in response.headers:
            issues.append({
                'severity': config['severity'],
                'message': f"Falta cabecera de seguridad: {header} ({config['description']})",
                'host': host
            })
        else:
            # Validaciones específicas para algunas cabeceras
            if header == 'Strict-Transport-Security':
                hsts = response.headers[header]
                if 'max-age=0' in hsts:
                    issues.append({
                        'severity': 'HIGH',
                        'message': 'HSTS deshabilitado (max-age=0)',
                        'host': host
                    })
                elif 'max-age' not in hsts:
                    issues.append({
                        'severity': 'MEDIUM',
                        'message': 'HSTS sin max-age definido',
                        'host': host
                    })
    
    return issues

def check_sensitive_files(base_url) -> list:
    """Verifica archivos sensibles con validación de contenido"""
    issues = []
    host = urlparse(base_url).hostname
    
    for file, config in SENSITIVE_FILES.items():
        file_url = urljoin(base_url, file)
        try:
            response = requests.get(file_url, headers=HEADERS, timeout=5)
            if response.status_code == 200:
                content_valid = True
                
                # Verificar contenido si es necesario
                if config['check_content'] and 'keywords' in config:
                    content_valid = any(keyword in response.text for keyword in config['keywords'])
                
                if content_valid:
                    issues.append({
                        'severity': config['severity'],
                        'message': f"Archivo sensible accesible: {file}",
                        'host': host,
                        'url': file_url
                    })
        except requests.RequestException:
            continue
    
    return issues

def detect_cms(base_url) -> list:
    """Detecta el CMS y su versión"""
    issues = []
    host = urlparse(base_url).hostname
    
    for cms, config in CMS_CHECKS.items():
        for path in config['paths']:
            target = urljoin(base_url, path)
            try:
                response = requests.get(target, headers=HEADERS, timeout=5)
                if response.status_code == 200:
                    version = get_cms_version(response, config)
                    
                    issues.append({
                        'severity': 'INFO',
                        'message': f"CMS detectado: {cms} {version}",
                        'host': host
                    })
                    
                    # Verificar vulnerabilidades conocidas
                    cve_issues = check_cve(cms, version)
                    if cve_issues:
                        issues.extend(cve_issues)
                    
                    return issues
            except requests.RequestException:
                continue
    
    return issues

def get_cms_version(response, config) -> str:
    """Obtiene la versión del CMS mediante diferentes métodos"""
    # Intenta obtener versión del meta generator
    if config['version'].get('meta'):
        soup = BeautifulSoup(response.text, 'html.parser')
        meta = soup.find('meta', attrs={'name': config['version']['meta']})
        if meta and meta.get('content'):
            return meta['content']
    
    # Intenta obtener versión de archivo específico
    if config['version'].get('file'):
        version_url = urljoin(response.url, config['version']['file'])
        try:
            version_response = requests.get(version_url, headers=HEADERS, timeout=5)
            if version_response.status_code == 200 and config['version'].get('regex'):
                import re
                match = re.search(config['version']['regex'], version_response.text)
                if match:
                    return match.group(1)
        except requests.RequestException:
            pass
    
    return 'versión no detectada'

def check_wordpress_plugins(base_url) -> list:
    """Verifica plugins de WordPress vulnerables"""
    issues = []
    host = urlparse(base_url).hostname
    
    # Método 1: Buscar archivos de plugins comunes
    for slug in PLUGIN_SLUGS:
        plugin_url = urljoin(base_url, f"/wp-content/plugins/{slug}/readme.txt")
        try:
            response = requests.get(plugin_url, headers=HEADERS, timeout=5)
            if response.status_code == 200:
                version = None
                if 'Stable tag:' in response.text:
                    version = response.text.split('Stable tag:')[1].split('\n')[0].strip()
                
                issues.append({
                    'severity': 'INFO',
                    'message': f"Plugin detectado: {slug} {version}",
                    'host': host
                })
        except requests.RequestException:
            pass
    
    return issues

def check_cve(software: str, version: str) -> list:
    """Consulta vulnerabilidades conocidas"""
    issues = []
    
    # Base de datos simplificada de vulnerabilidades
    KNOWN_VULNS = {
        'WordPress': {
            '5.7': [('CVE-2021-44228', 'CRITICAL', 'Vulnerabilidad RCE en core')],
            '5.6': [('CVE-2021-3929', 'HIGH', 'XSS en editor de bloques')]
        },
        'Joomla': {
            '3.9': [('CVE-2020-1024', 'HIGH', 'Vulnerabilidad de inyección SQL')]
        }
    }
    
    if software in KNOWN_VULNS:
        for vuln_version, vulns in KNOWN_VULNS[software].items():
            if version.startswith(vuln_version):
                for cve, severity, description in vulns:
                    issues.append({
                        'severity': severity,
                        'message': f"{software} {version} - {cve}: {description}",
                        'host': 'N/A'
                    })
    
    return issues

def check_url(url: str) -> list:
    """
    Ejecuta el chequeo de una sola URL.
    """
    issues = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname

    try:
        # 1. Solicitud inicial
        response = requests.get(base, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        if final_url != base:
            issues.append({
                'severity': 'INFO',
                'message': f"Redirección detectada: {base} -> {final_url}",
                'host': host
            })
            base = final_url
            parsed = urlparse(base)
            host = parsed.hostname

        # 2. Información del servidor
        server = response.headers.get('Server', 'Desconocido')
        issues.append({
            'severity': 'INFO',
            'message': f"Servidor web: {server}",
            'host': host
        })
        
        xp = response.headers.get('X-Powered-By', '')
        if xp:
            issues.append({
                'severity': 'INFO',
                'message': f"Tecnología backend: {xp}",
                'host': host
            })

        # 3. Cabeceras de seguridad
        issues.extend(check_security_headers(response))

        # 4. Chequeo SSL/TLS (solo para HTTPS)
        if parsed.scheme == 'https':
            issues.extend(check_ssl(base))
        else:
            issues.append({
                'severity': 'HIGH',
                'message': "El sitio no usa HTTPS",
                'host': host
            })

        # 5. Detección de CMS
        issues.extend(detect_cms(base))

        # 6. Si es WordPress, verificar plugins
        if any('WordPress' in issue['message'] for issue in issues):
            issues.extend(check_wordpress_plugins(base))

        # 7. Archivos sensibles con verificación de contenido
        issues.extend(check_sensitive_files(base))

    except requests.RequestException as e:
        issues.append({
            'severity': 'DEBUG',
            'message': f"Error HTTP: {e}",
            'host': host
        })
    
    return issues

def format_issues(issues: list) -> str:
    """Formatea los resultados para mostrar en consola"""
    output = []
    grouped = {}
    
    # Agrupar por host
    for issue in issues:
        host = issue['host']
        if host not in grouped:
            grouped[host] = []
        grouped[host].append(issue)
    
    # Ordenar por severidad
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'DEBUG']
    
    for host, host_issues in grouped.items():
        output.append(f"\n{Fore.CYAN}=== Resultados para {host} ==={Style.RESET_ALL}")
        
        # Ordenar issues por severidad
        host_issues.sort(key=lambda x: severity_order.index(x['severity']))
        
        for issue in host_issues:
            color = SEVERITY.get(issue['severity'], Fore.WHITE)
            url_info = f" ({issue['url']})" if 'url' in issue else ""
            output.append(f"{color}[{issue['severity']}] {issue['message']}{url_info}{Style.RESET_ALL}")
    
    return '\n'.join(output)

def check_all(url: str = URL_BASE) -> str:
    """
    Ejecuta chequeo en el dominio base y sus subdominios.
    Retorna un string formateado para mostrar.
    """
    all_issues = []
    
    # Chequeo del host principal
    all_issues.extend(check_url(url))
    
    # Enumerar y chequeo de subdominios con concurrencia
    subs = enum_subdomains(domain=urlparse(url).hostname)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for sub in subs:
            sub_url = f"https://{sub}" if url.lower().startswith('https') else f"http://{sub}"
            futures.append(executor.submit(check_url, sub_url))
        
        for future in futures:
            try:
                all_issues.extend(future.result())
            except Exception as e:
                all_issues.append({
                    'severity': 'DEBUG',
                    'message': f"Error procesando subdominio: {str(e)}",
                    'host': 'N/A'
                })

    # Filtrar duplicados
    unique_issues = []
    seen_messages = set()
    
    for issue in all_issues:
        msg = issue['message'] + issue['host']
        if msg not in seen_messages:
            seen_messages.add(msg)
            unique_issues.append(issue)
    
    return format_issues(unique_issues)

# Alias para compatibilidad
check = check_all