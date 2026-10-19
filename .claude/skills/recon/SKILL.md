---
name: recon
description: Reconocimiento y OSINT con 0ctopus — enumeración de subdominios, registros DNS, WHOIS, geolocalización de IPs y URLs históricas. Usar para mapear la superficie de ataque de un dominio antes de las fases activas.
---

# Skill: Reconocimiento (0ctopus)

Guía para mapear la superficie de ataque de un objetivo con las herramientas de recon de 0ctopus. Ejecutar siempre desde la raíz del proyecto: `python 0ctopus.py <comando>`.

## Herramientas

### enum-subdomains
```bash
python 0ctopus.py enum-subdomains --domain <dominio>
```
Combina certificados (crt.sh), wordlist local y resolución DNS. Sin `--domain` usa `config.py`.
Salida: lista de subdominios + `output/subdomains-<dominio>.txt` + HTML.

### dns-recon
```bash
python 0ctopus.py dns-recon <dominio>
```
Registros A, AAAA, MX, NS, TXT, CNAME, SOA. Fijate en:
- **TXT**: SPF/DMARC/DKIM (postura antispoofing).
- **MX**: proveedor de correo.
- **NS**: proveedor DNS.

### whois
```bash
python 0ctopus.py whois <dominio>
```
Registrador, fechas de creación/expiración, nameservers, estado, emails, DNSSEC.

### wayback-urls
```bash
python 0ctopus.py wayback-urls <dominio> [--limit N]
```
URLs históricas desde el Internet Archive. Útil para descubrir endpoints viejos, paneles, parámetros.

### geoip
```bash
python 0ctopus.py geoip <ip>
```
País, ciudad, ISP, organización, ASN de una IP (p. ej. la del registro A).

## Metodología

1. `enum-subdomains` + `dns-recon` para el mapa inicial.
2. `whois` para contexto de propiedad y antigüedad.
3. `wayback-urls` para superficie histórica.
4. `geoip` sobre las IPs resueltas.

## Interpretación → hallazgos

- Falta de SPF/DMARC → riesgo de spoofing de correo (Medio).
- Subdominios olvidados/dev/staging expuestos → posible superficie insegura (Medio/Alto).
- DNSSEC deshabilitado → informativo/Bajo.
- Dominio por expirar → informativo.

Cada comando deja su HTML en `output/reports/` y actualiza `output/index.html`. Reportá solo datos reales de la salida.
