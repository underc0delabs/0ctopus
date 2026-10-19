# Arquitectura

![Arquitectura](assets/architecture.svg)

## Componentes

```
0ctopus/
├── 0ctopus.py            # CLI principal (click) + menú interactivo
├── config.py             # HOST / URL_BASE por defecto
├── requirements.txt
├── tools/                # Herramientas (una por archivo)
│   ├── report.py         # Motor de reportes HTML + dashboard
│   ├── portscanner.py, vuln_check.py, dirb.py, subdomain_enum.py,
│   ├── packet_sniffer.py, dns_recon.py, whois_lookup.py, ip_geolocator.py,
│   ├── wayback_urls.py, header_analyzer.py, admin_finder.py, hash_identify.py,
│   ├── arp_scan.py, wifi_scanner.py, wifi_handshake.py, handshake_crack.py
├── .claude/
│   ├── agents/           # Orquestador + 300+ subagentes + catálogo
│   └── skills/           # Skills de dominio
├── docs/                 # Esta documentación (md, web, imágenes, PDF)
└── output/               # Reportes generados (gitignored)
```

## Flujo de una herramienta

1. El comando `click` en `0ctopus.py` (o el módulo) recibe el objetivo.
2. Llama a la función de la herramienta en `tools/`.
3. Guarda la salida clásica (TXT/JSON/PCAP) en `output/`.
4. Llama a `report.save(...)` → genera el HTML del reporte, actualiza `reports.json` y regenera `index.html`.

## Flujo agéntico

1. `pentest-orchestrator` planifica y delega (tool `Agent`) en especialistas.
2. Cada especialista ejecuta tools de 0ctopus (vía `Bash`) y/o metodología de su `Skill`.
3. Los reportes individuales caen en `output/reports/`.
4. `report-writer` consolida todo en un reporte `engagement` con `report-build`.

## Principios de diseño

- **Una herramienta = un archivo** en `tools/`, con comando `click` y reporte HTML.
- **Salida unificada** en `output/` (gitignored).
- **Objetivo configurable** por `config.py` o por argumento.
- **Agentes self-contained** con guard de autorización y referencia a su skill.
