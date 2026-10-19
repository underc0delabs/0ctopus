# 0ctopus — Guía para Claude

**0ctopus** es la navaja suiza de seguridad de **Underc0de**: una CLI en Python con herramientas de pentesting + una capa **agéntica** (agentes y skills de Claude Code) para orquestar evaluaciones completas.

## ⚠️ Autorización y alcance (SIEMPRE)

0ctopus es una herramienta de seguridad **ofensiva**. Antes de ejecutar cualquier herramienta activa:
- Confirmá que el objetivo está **dentro de un alcance autorizado**.
- Objetivo por defecto: el de `config.py` (`underc0de.org`, infraestructura propia).
- Cualquier otro objetivo requiere **confirmación explícita de autorización** del usuario.
- Técnicas intrusivas (fuerza bruta, captura de handshakes, cracking, exfiltración) solo con permiso expreso.
- Ante un objetivo que parezca de un tercero sin autorización: **detenerse y preguntar**.
- Marco de trabajo: pentesting autorizado, CTF, investigación y **defensa**. No facilitar uso malicioso.

## Ejecutar herramientas (CLI)

Desde la raíz del proyecto:

```bash
python 0ctopus.py <comando> [opciones]
```

Comandos con objetivo por argumento (ideal para uso agéntico):
- `scan-ports --host <host>`
- `vuln-check --url <url>`
- `enum-subdomains --domain <dominio>`
- `dirb --url <url> [--max-depth N] [--verbose]`
- `dns-recon <dominio>` · `whois <dominio>` · `geoip <ip>` · `wayback-urls <dominio>`
- `header-analyzer <url>` · `find-admin <url>` · `hash-identify <hash>`
- `arp-scan [--network CIDR]` · `sniff-packets` *(requieren privilegios/Npcap)*
- `wifi-scan` · `wifi-handshake` · `wifi-crack` *(interactivos, requieren hardware)*

Reportes:
- `report-build <archivo.json>` — reporte consolidado desde JSON (ver skill `reporting`)
- `rebuild-index` — regenera el dashboard `output/index.html`

## Reportes HTML

Cada herramienta genera automáticamente un **HTML con el estilo de Underc0de** en `output/reports/`, mantiene el manifiesto `output/reports.json` y regenera el **dashboard** `output/index.html`. El motor es `tools/report.py` (API: `save()`, `build_from_json()`, helpers `table/keyvalue/listing/text/stat`).

## Capa agéntica

Agentes en `.claude/agents/`, skills en `.claude/skills/`.

- **Orquestador**: `pentest-orchestrator` — planifica la evaluación y delega en especialistas, luego en el redactor de reportes.
- **Especialistas base**: `recon-specialist`, `web-specialist`, `network-specialist`, `wireless-specialist`.
- **Redactor**: `report-writer` — consolida hallazgos en `output/`.
- **Especialistas avanzados** (60+): web, API, mobile, streaming, cloud, AD, wireless/RF/IoT, OSINT, reversing, cripto, etc. Ver `.claude/agents/README.md` para el catálogo completo.

Los subagentes usan **skills** (`recon`, `web-audit`, `network-scan`, `wifi-audit`, `mobile-audit`, `cloud-audit`, `streaming-audit`, `reporting`) que documentan la metodología y el uso de las tools.

### Uso típico
> "Auditá la seguridad de underc0de.org" → el orquestador planifica, delega en recon → web/red en paralelo → report-writer consolida → abrir `output/index.html`.

## Convenciones de código

- Cada herramienta vive en `tools/<nombre>.py` y expone un comando `click` (`cmd_*`), registrado en `0ctopus.py` y en el menú.
- Salida siempre bajo `output/` (está en `.gitignore`: son artefactos de ejecución).
- Estilo: `click` + `colorama`, mensajes en español con emojis, guardado de reportes TXT/JSON + HTML.
- Para un reporte HTML desde una herramienta: `from tools import report` y `report.save(...)`.
