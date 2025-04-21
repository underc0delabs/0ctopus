# Archivo: tools/dirb.py

import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import URL_BASE
from bs4 import BeautifulSoup

# Configuración de crawling
MAX_DEPTH = 2       # Profundidad máxima de crawling
TIMEOUT = 5         # Timeout en segundos para peticiones HTTP
MAX_WORKERS = 10    # Número de hilos concurrentes por nivel


def is_directory_path(path: str) -> bool:
    """
    Determina si 'path' representa un directorio válido:
    - No es root '/'
    - El segmento final no contiene un punto (sin extensión)
    """
    if path == '/':
        return False
    segment = path.rstrip('/').split('/')[-1]
    return '.' not in segment


def crawl_links(base_url: str = URL_BASE,
                max_depth: int = MAX_DEPTH,
                max_workers: int = MAX_WORKERS,
                verbose: bool = False) -> list[tuple[str,int]]:
    """
    Realiza crawling de enlaces internos hasta max_depth de manera concurrente.
    Filtra query strings y sesiones (PHPSESSID), y devuelve solo directorios.

    Retorna: lista de tuplas (path, status_code) ordenadas por path.
    """
    session = requests.Session()
    session.headers.update({'User-Agent': '0ctopus-bot'})
    domain = urlparse(base_url).netloc
    visited = set()
    found = []
    to_crawl = {base_url}

    for depth in range(max_depth + 1):
        if verbose:
            print(f"[Depth {depth}] URLs en cola: {len(to_crawl)}")
        next_level = set()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(session.get, url, timeout=TIMEOUT): url for url in to_crawl if url not in visited}
            for future in as_completed(future_map):
                url = future_map[future]
                visited.add(url)
                try:
                    resp = future.result()
                    status = resp.status_code
                except Exception as e:
                    if verbose:
                        print(f"[-] Error al solicitar {url}: {e}")
                    continue

                # Limpieza de URL (sin query strings)
                clean_url = url.split('?')[0]
                # Saltar sesiones
                if 'PHPSESSID' in url:
                    if verbose:
                        print(f"[Skip] Sesión detectada en {url}")
                    continue

                # Registrar solo paths de directorios
                path = urlparse(clean_url).path or '/'
                if status < 400 and is_directory_path(path):
                    found.append((path, status))

                # Extraer enlaces para siguiente nivel
                content_type = resp.headers.get('Content-Type', '').lower()
                if depth < max_depth and 'html' in content_type:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href'].split('#')[0]
                        full = urljoin(base_url, href).split('?')[0]
                        if urlparse(full).netloc == domain and full not in visited:
                            next_level.add(full)

        to_crawl = next_level

    # Deduplicación, conservando el status más bajo
    unique = {}
    for path, status in found:
        if path not in unique or status < unique[path]:
            unique[path] = status

    return sorted(unique.items(), key=lambda x: x[0])


def brute_force(base_url: str = URL_BASE, wordlist: str = 'paths.txt') -> list[tuple[str,int]]:
    """
    Alias para compatibilidad: utiliza crawling inteligente para descubrir directorios.
    """
    return crawl_links(base_url)
