---
name: web-audit
description: Auditoría de seguridad web con 0ctopus — cabeceras de seguridad, chequeo de vulnerabilidades (TLS, CVEs, archivos sensibles, WordPress), crawling de directorios y búsqueda de paneles de administración. Usar para evaluar aplicaciones/sitios HTTP/HTTPS.
---

# Skill: Auditoría Web (0ctopus)

Guía para evaluar la superficie web de un objetivo. Ejecutar desde la raíz: `python 0ctopus.py <comando>`.

## ⚠️ Alcance
Solo contra objetivos autorizados. `dirb` y `find-admin` generan tráfico notable; ajustá profundidad/hilos y confirmá autorización para intrusividad alta.

## Herramientas

### header-analyzer (no intrusivo, empezar por acá)
```bash
python 0ctopus.py header-analyzer <url>
```
Audita HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, y fingerprint (`Server`, `X-Powered-By`).

### vuln-check (análisis principal)
```bash
python 0ctopus.py vuln-check --url <url>
```
Revisa SSL/TLS, cabeceras, archivos sensibles (`.git`, `.env`, backups), plugins de WordPress y CVEs conocidas por software/versión. Sin `--url` usa `config.py`.

### dirb (descubrimiento de directorios)
```bash
python 0ctopus.py dirb --url <url> --max-depth 2 [--verbose]
```
Crawling interno; devuelve rutas con su código de estado.

### find-admin (paneles de administración)
```bash
python 0ctopus.py find-admin <url> [-w wordlist] [-t 10] [--timeout 5]
```
Prueba rutas comunes y marca las que parecen panel (200 + formulario con campo password).

## Metodología

1. `header-analyzer` → fingerprint + postura de cabeceras.
2. `vuln-check --url` → hallazgos principales.
3. `dirb --url` → mapa de rutas.
4. `find-admin` → superficie administrativa.

## Interpretación → severidad

- Archivos sensibles expuestos (`.git`, `.env`) → **Alta**.
- CVE conocida en software detectado → **Alta/Media** según CVSS.
- TLS débil / certificado inválido / sin HSTS → **Media**.
- Falta de CSP / X-Frame-Options → **Media/Baja**.
- Banner de servidor con versión → **Baja** (fingerprinting).
- Panel de admin accesible → **Media/Alta** según exposición.

Cada comando deja su HTML en `output/reports/`. Reportá hallazgos con evidencia real de la salida; no inventes vulnerabilidades.
