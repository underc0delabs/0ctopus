# Uso

## Menú interactivo

Sin argumentos, 0ctopus muestra un menú:

```bash
python 0ctopus.py
```

## Comandos directos

```bash
python 0ctopus.py <comando> [opciones]
```

Muchos comandos aceptan el **objetivo por argumento**; si se omite, usan `config.py`.

### Reconocimiento
```bash
python 0ctopus.py enum-subdomains --domain ejemplo.com
python 0ctopus.py dns-recon ejemplo.com
python 0ctopus.py whois ejemplo.com
python 0ctopus.py wayback-urls ejemplo.com --limit 500
python 0ctopus.py geoip 1.2.3.4
```

### Web
```bash
python 0ctopus.py header-analyzer https://ejemplo.com
python 0ctopus.py vuln-check --url https://ejemplo.com
python 0ctopus.py dirb --url https://ejemplo.com --max-depth 3 --verbose
python 0ctopus.py find-admin https://ejemplo.com
```

### Red
```bash
python 0ctopus.py scan-ports --host ejemplo.com
python 0ctopus.py arp-scan --network 192.168.1.0/24      # requiere privilegios
python 0ctopus.py sniff-packets --timeout 20             # requiere privilegios
```

### Wireless / hashes
```bash
python 0ctopus.py wifi-scan            # interactivo, requiere hardware
python 0ctopus.py wifi-handshake       # interactivo, requiere modo monitor
python 0ctopus.py wifi-crack           # interactivo, requiere hashcat
python 0ctopus.py hash-identify '$2b$12$...'
```

### Reportes
```bash
python 0ctopus.py report-build output/engagement.json   # reporte consolidado
python 0ctopus.py rebuild-index                         # regenera el dashboard
```

## Salida

Todo se guarda en `output/`:
- `output/index.html` — **dashboard** (abrir en el navegador).
- `output/reports/*.html` — un reporte HTML por ejecución.
- Archivos `.txt` / `.json` / `.pcap` según la herramienta.

Ver [reporting.md](reporting.md) para el detalle de los reportes.
