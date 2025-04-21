# Archivo: tools/vuln_check.py

import requests
import ssl
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from config import URL_BASE
from tools.subdomain_enum import enumerate as enum_subdomains

# Plugins comunes para WordPress
PLUGIN_SLUGS = [
    'woocommerce',
    'contact-form-7',
    'yoast-seo',
]

# Configuración para detectar CMS y endpoints para versión
CMS_CHECKS = {
    'WordPress': {
        'path': '/wp-login.php',
        'version_path': '/readme.html'
    },
    'Joomla': {
        'path': '/administrator/',
        'version_meta': True
    },
    'Drupal': {
        'path': '/user/login',
        'version_meta': True
    },
    'Magento': {
        'path': '/skin/frontend/',
        'version_meta': True
    },
    'PrestaShop': {
        'path': '/admin-dev/',
        'version_meta': True
    },
    'phpBB': {
        'path': '/viewforum.php',
        'version_meta': True
    },
    'SMF': {
        'path': '/',  # SMF detection via meta or homepage text
        'version_meta': True
    },
    'vBulletin': {
        'path': '/forum/',
        'version_meta': True
    },
}


def check_url(url: str) -> list[str]:
    """
    Ejecuta el chequeo de una sola URL.
    """
    issues = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 1. Headers HTTP
    try:
        r = requests.get(base, timeout=5)
        server = r.headers.get('Server', 'Desconocido')
        issues.append(f"[{parsed.netloc}] Server header: {server}")
        xp = r.headers.get('X-Powered-By', '')
        if xp:
            issues.append(f"[{parsed.netloc}] X-Powered-By: {xp}")
    except requests.RequestException as e:
        issues.append(f"[{parsed.netloc}] Error HTTP: {e}")
        return issues

    # 2. HTTPS disponible?
    if not base.lower().startswith('https'):
        https_url = base.replace('http://', 'https://')
        try:
            r2 = requests.get(https_url, timeout=5)
            if r2.status_code < 400:
                issues.append(f"[{parsed.netloc}] HTTPS disponible en: {https_url}")
            else:
                issues.append(f"[{parsed.netloc}] Sitio NO usa HTTPS")
        except requests.RequestException:
            issues.append(f"[{parsed.netloc}] Sitio NO usa HTTPS")

    # 3. Certificado SSL
    try:
        host = parsed.hostname
        port = parsed.port or (443 if base.lower().startswith('https') else 80)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, port))
            cert = s.getpeercert()
            not_after = cert.get('notAfter')
            issues.append(f"[{parsed.netloc}] Certificado SSL válido (expira: {not_after})")
    except Exception as e:
        issues.append(f"[{parsed.netloc}] Error SSL: {e}")

    # 4. Meta generator
    soup = BeautifulSoup(r.text, 'html.parser')
    meta = soup.find('meta', attrs={'name': 'generator'})
    meta_content = meta['content'] if meta and meta.get('content') else ''
    if meta_content:
        issues.append(f"[{parsed.netloc}] Meta generator: {meta_content}")

    # 5. Detección de CMS y versiones
    detected = False
    for cms, opts in CMS_CHECKS.items():
        path = opts.get('path', '/')
        detect_url = urljoin(base, path)
        if cms == 'SMF':
            if 'SMF' in meta_content or 'Simple Machines Forum' in r.text:
                issues.append(f"[{parsed.netloc}] Detectado CMS SMF en: {base}")
                detected = True
        else:
            try:
                rc = requests.get(detect_url, timeout=5)
                if rc.status_code < 400:
                    issues.append(f"[{parsed.netloc}] Detectado CMS {cms} en: {detect_url}")
                    detected = True
                    # Versión mediante path o meta
                    if opts.get('version_path'):
                        vr_url = urljoin(base, opts['version_path'])
                        vr = requests.get(vr_url, timeout=5)
                        if vr.status_code < 400 and '<h1>' in vr.text:
                            ver = vr.text.split('<h1>')[1].split('</h1>')[0]
                            issues.append(f"[{parsed.netloc}] {cms} versión: {ver}")
                    elif opts.get('version_meta'):
                        soup2 = BeautifulSoup(rc.text, 'html.parser')
                        meta2 = soup2.find('meta', attrs={'name': 'generator'})
                        if meta2 and meta2.get('content'):
                            issues.append(f"[{parsed.netloc}] {cms} versión (meta): {meta2['content']}")
            except requests.RequestException:
                continue
        if detected:
            break

    # 6. Plugins de WordPress (verificar style.css)
    if any('CMS WordPress' in issue for issue in issues):
        for slug in PLUGIN_SLUGS:
            style_url = urljoin(base, f"/wp-content/plugins/{slug}/style.css")
            try:
                spr = requests.get(style_url, timeout=5)
                if spr.status_code == 200:
                    issues.append(f"[{parsed.netloc}] Plugin activo: {slug} (style.css encontrado)")
            except requests.RequestException:
                pass

    return issues


def check_all(url: str = URL_BASE) -> list[str]:
    """
    Ejecuta chequeo en el dominio base y sus subdominios.
    """
    all_issues = []
    # Chequeo del host principal
    all_issues.extend(check_url(url))
    # Enumerar y chequeo de subdominios
    subs = enum_subdomains(domain=urlparse(url).hostname)
    for sub in subs:
        sub_url = f"https://{sub}" if url.lower().startswith('https') else f"http://{sub}"
        all_issues.append(f"--- Chequeando subdominio: {sub_url}")
        all_issues.extend(check_url(sub_url))
    # Eliminar duplicados y ordenar
    unique = list(dict.fromkeys(all_issues))
    return sorted(unique)

# Alias para compatibilidad: check() invoca a check_all()
check = check_all
