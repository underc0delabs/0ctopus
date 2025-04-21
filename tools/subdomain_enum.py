# Archivo: tools/subdomain_enum.py

import requests
import dns.resolver
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import HOST as DEFAULT_DOMAIN

# Número de hilos para resolución
MAX_WORKERS = 20
# Timeout DNS
DNS_TIMEOUT = 2
# URL CRT.SH API
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def fetch_ct_log_subdomains(domain: str) -> set[str]:
    """
    Consulta crt.sh para obtener subdominios desde logs de certificados.
    Devuelve un set de nombres únicos.
    """
    try:
        url = CRT_SH_URL.format(domain=domain)
        resp = requests.get(url, timeout=5)
        data = resp.json()
        subs = set()
        for entry in data:
            name = entry.get('name_value', '')
            # Puede haber múltiples nombres por entry
            for sub in name.split('\n'):
                sub = sub.strip().lower()
                if sub and sub.endswith(domain) and '*' not in sub:
                    subs.add(sub)
        return subs
    except Exception:
        return set()


def resolve_host(host: str) -> bool:
    """
    Intenta resolver host a una IP.
    Retorna True si hay al menos un registro A o CNAME.
    """
    try:
        answers = dns.resolver.resolve(host, 'A', lifetime=DNS_TIMEOUT)
        return True
    except Exception:
        # Intentar CNAME
        try:
            dns.resolver.resolve(host, 'CNAME', lifetime=DNS_TIMEOUT)
            return True
        except Exception:
            return False


def enumerate(domain: str = DEFAULT_DOMAIN,
              wordlist: str = 'subdomains.txt',
              include_ct: bool = True,
              verbose: bool = False) -> list[str]:
    """
    Enumera subdominios de un dominio:
      1. Obtiene candidatos de crt.sh (si include_ct).
      2. Agrega wordlist local.
      3. Elimina duplicados y nombres sin sufijo dominio.
      4. Resuelve en DNS concurrentemente y devuelve solo los que existan.

    Parámetros:
      domain: dominio base
      wordlist: archivo de palabras para brute-force
      include_ct: usar crt.sh
      verbose: imprimir progreso

    Retorna lista de subdominios ordenada.
    """
    domain = domain.lower().strip()
    candidates = set()

    # 1. Cert Transparency
    if include_ct:
        if verbose:
            print(f"[+] Consultando crt.sh para {domain}...")
        candidates |= fetch_ct_log_subdomains(domain)

    # 2. Wordlist
    try:
        with open(wordlist, 'r') as f:
            for line in f:
                name = line.strip().lower()
                if name:
                    fqdn = f"{name}.{domain}"
                    candidates.add(fqdn)
    except FileNotFoundError:
        if verbose:
            print(f"[!] Wordlist {wordlist} no encontrada.")

    # Limpiar
    candidates = {c for c in candidates if c.endswith(domain)}

    # 3. Resolver DNS concurrentemente
    if verbose:
        print(f"[+] Resolviendo {len(candidates)} candidatos... (threads={MAX_WORKERS})")
    valid = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(resolve_host, host): host for host in candidates}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                if future.result():
                    valid.append(host)
                    if verbose:
                        print(f"    ✔ {host}")
            except Exception:
                pass

    return sorted(valid)
