# tools/dirb.py

import requests
from config import URL_BASE

def brute_force(base_url: str = URL_BASE, wordlist: str = 'paths.txt') -> list[tuple[str,int]]:
    """
    Fuerza bruta de rutas en base_url usando wordlist.
    Si no se pasa base_url, usa la URL_BASE de config.py.
    Devuelve lista de (ruta, status_code) para respuestas < 400.
    """
    hallazgos = []
    try:
        with open(wordlist, 'r') as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return hallazgos

    base = base_url.rstrip('/')
    for p in paths:
        target = f"{base}/{p}"
        try:
            r = requests.get(target, timeout=2)
            if r.status_code < 400:
                hallazgos.append((target, r.status_code))
        except requests.RequestException:
            continue
    return hallazgos
