# Referencia de herramientas

Cada herramienta vive en `tools/<nombre>.py`, expone un comando `click` y genera un **reporte HTML** en `output/reports/`.

| Comando | Descripción | Objetivo |
|---------|-------------|----------|
| `scan-ports` | Escaneo de puertos comunes con detección de servicio/versión | `--host` |
| `vuln-check` | Chequeo de vulnerabilidades (TLS, cabeceras, archivos sensibles, WordPress, CVEs) | `--url` |
| `enum-subdomains` | Subdominios vía crt.sh + wordlist + DNS | `--domain` |
| `dirb` | Crawling de directorios internos | `--url`, `--max-depth`, `--verbose` |
| `sniff-packets` | Captura de paquetes a `.pcap` | `--interface`, `--count`, `--timeout` |
| `dns-recon` | Registros A/AAAA/MX/NS/TXT/CNAME/SOA | `<dominio>` |
| `whois` | Datos WHOIS del dominio | `<dominio>` |
| `geoip` | Geolocalización de IP | `<ip>` |
| `wayback-urls` | URLs históricas (Wayback Machine) | `<dominio>`, `--limit` |
| `header-analyzer` | Auditoría de cabeceras de seguridad HTTP | `<url>` |
| `find-admin` | Búsqueda de paneles de administración | `<url>`, `-w`, `-t` |
| `hash-identify` | Identifica el tipo probable de un hash | `<hash>` |
| `arp-scan` | Descubre hosts en la LAN (ARP) | `--network`, `--timeout` |
| `wifi-scan` | Escanea redes WiFi cercanas | *(interactivo)* |
| `wifi-handshake` | Captura handshake WPA/WPA2 | *(interactivo)* |
| `wifi-crack` | Crackea handshake con hashcat | *(interactivo)* |
| `report-build` | Reporte HTML consolidado desde JSON | `<json>` |
| `rebuild-index` | Regenera el dashboard | — |

## Notas por categoría

- **Red** (`scan-ports`, `arp-scan`, `sniff-packets`): `arp-scan` y `sniff-packets` requieren privilegios (admin/root) y, en Windows, Npcap.
- **Wireless** (`wifi-*`): requieren hardware compatible y son interactivas.
- **Recon** (`dns-recon`, `whois`, `wayback-urls`, `geoip`, `enum-subdomains`): rápidas y poco intrusivas; ideales para mapear la superficie.
- **Web** (`vuln-check`, `header-analyzer`, `dirb`, `find-admin`): `dirb`/`find-admin` generan tráfico notable; ajustá parámetros y confirmá autorización.

## Añadir una herramienta nueva

1. Creá `tools/mi_tool.py` con un comando `@click.command(name='mi-tool')` (`cmd_*`).
2. Al final, generá el reporte: `from tools import report; report.save(tool='mi-tool', title=..., target=..., sections=[...], stats=[...])`.
3. Registrala en `0ctopus.py` (`from tools.mi_tool import cmd_mi_tool` + `cli.add_command(...)`) y agregala al menú.
