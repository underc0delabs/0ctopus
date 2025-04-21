# tools/subdomain_enum.py

import requests
from config import HOST as DEFAULT_DOMAIN

def enumerate(domain: str = DEFAULT_DOMAIN, wordlist: str = 'subdomains.txt') -> list[str]:
    """
    Lee una wordlist y prueba http://sub.domain.
    Si no se pasa domain, usa el HOST de config.py.
    Devuelve los subdominios activos (status_code < 400).
    """
    encontrados = []
    try:
        with open(wordlist, 'r') as f:
            subs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return encontrados

    for sub in subs:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                encontrados.append(url)
        except requests.RequestException:
            continue
    return encontrados
