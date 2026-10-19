# 0ctopus

[![GitHub Repo](https://img.shields.io/badge/Repo-0ctopus-blue)](https://github.com/underc0delabs/0ctopus)

**0ctopus** es una navaja suiza de seguridad informática desarrollada por Underc0de Labs. Proporciona varias herramientas de pentesting y análisis a través de un menú interactivo o comandos directos.

---

## 🔧 Características

- Escaneo de puertos avanzado con detección de servicios y versiones.
- Enumeración de subdominios (incluyendo crt.sh y wordlist local).
- Crawling de directorios internos con salida formateada.
- Chequeo rápido de vulnerabilidades en URL base.
- Captura de paquetes de red (exporta .pcap).
- Geolocalización de direcciones IP.
- Consultas WHOIS de dominios.
- Búsqueda de paneles de administración.
- Escaneo de redes WiFi, captura de handshakes y cracking de handshakes.
- Reconocimiento DNS (A/AAAA/MX/NS/TXT/CNAME/SOA).
- Análisis de cabeceras de seguridad HTTP.
- Identificación del tipo de hash.
- URLs históricas desde el Wayback Machine.
- Descubrimiento de hosts en la red local (ARP scan).
- Menú interactivo para elegir funcionalidad.

---

## 📦 Instalación

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/underc0delabs/0ctopus.git
   cd 0ctopus
   ```
2. Crear y activar un entorno virtual (opcional, pero recomendado):
   ```bash
   python3 -m venv env
   source env/bin/activate    # Linux/macOS
   env\\Scripts\\activate     # Windows
   ```
3. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

**Requisitos adicionales en Windows**:
- Instalar **Npcap** en modo "WinPcap Compatible Mode" desde https://nmap.org/npcap
- Ejecutar la terminal **como Administrador** para permitir la captura de paquetes.

---

## ⚙️ Configuración

Antes de ejecutar cualquier comando, edita el archivo `config.py` definiendo:

```python
HOST = "dominio.com"         # Host objetivo para escaneos y enumeraciones
URL_BASE = "https://.../"   # URL base para crawling y chequeo de vulnerabilidades
```

---

## 🚀 Uso

### Menú interactivo

Sin argumentos, muestra el menú:
```bash
python 0ctopus.py
```

### Comandos directos

| Opción               | Descripción                                                      |
|----------------------|------------------------------------------------------------------|
| `scan-ports`         | Escaneo de puertos avanzado (salida en `output/port_scan-<HOST>.txt`) |
| `vuln-check`         | Chequeo de vulnerabilidades (salida en `output/vuln_check-<HOST>.txt`) |
| `enum-subdomains`    | Enumeración de subdominios (`output/subdomains-<HOST>.txt`)      |
| `dirb`               | Crawling de directorios internos (`output/dirb_scan-<HOST>.txt`) |
|                      | - `--max-depth N` Profundidad máxima (por defecto 2)             |
|                      | - `--verbose`     Muestra progreso en consola                   |
| `sniff-packets`      | Captura paquetes de red en `.pcap` (`output/packets-<HOST>.pcap`)|
|                      | - `--interface` Interfaz de captura · `--count` Nº paquetes · `--timeout` Segundos |
| `geoip <IP>`         | Geolocaliza una dirección IP                                     |
| `whois <dominio>`    | Consulta WHOIS de un dominio                                     |
| `find-admin <URL>`   | Busca paneles de administración en la URL base                   |
| `wifi-scan`          | Escanea redes WiFi cercanas                                      |
| `wifi-handshake`     | Captura un handshake WiFi                                        |
| `wifi-crack`         | Intenta crackear un handshake capturado                          |
| `dns-recon [dominio]`| Registros DNS A/AAAA/MX/NS/TXT/CNAME/SOA (dominio opcional, usa `config.py`) |
| `header-analyzer [url]` | Audita cabeceras de seguridad HTTP (URL opcional, usa `config.py`) |
| `hash-identify <hash>` | Identifica el tipo probable de un hash                        |
| `wayback-urls [dominio]`| URLs históricas desde el Wayback Machine (`--limit N`)        |
| `arp-scan`           | Descubre hosts en la LAN (`--network CIDR`, `--timeout N`)       |

**Ejemplo:**
```bash
python 0ctopus.py dirb --max-depth 3 --verbose
```

---

## 📂 Salida

Todos los resultados se guardan en la carpeta `output/`. Los nombres de archivo incluyen el comando y el `HOST` configurado.

### 📊 Reportes HTML y dashboard

Además de los archivos de texto/JSON/PCAP, **cada ejecución genera un reporte HTML** con el estilo visual de Underc0de:

```
output/
├── index.html          ← Dashboard general (abrir en el navegador)
├── reports.json        ← Manifiesto de todos los reportes
└── reports/
    ├── scan-ports-underc0de.org-20260101_120000.html
    ├── whois-underc0de.org-20260101_120500.html
    └── ...
```

- **`output/index.html`** es un **dashboard** con métricas globales (total de reportes, herramientas usadas, objetivo principal, último escaneo), buscador y filtros por herramienta, y un listado enlazado a cada reporte.
- Cada herramienta produce **un HTML individual** con tarjetas de métricas, tablas con estados coloreados, datos clave-valor y la salida en crudo.

> Abrí `output/index.html` en tu navegador para navegar todos los reportes.

Los reportes usan la estética **"acid lab"** de Underc0de: fondo negro con grilla y **scanlines CRT**, glow neón celeste, tipografía **Pixelify Sans** (HUD) + monospace, cabecera tipo terminal (`root@underc0de:~/0ctopus#`), cursor parpadeante y badges de severidad con glow.

---

## 🤖 Uso agéntico con Claude

0ctopus incluye una capa de **agentes y skills** para Claude Code (`.claude/`), que permite orquestar evaluaciones completas.

- **Orquestador**: `pentest-orchestrator` planifica y delega.
- **Especialistas base**: `recon-specialist`, `web-specialist`, `network-specialist`, `wireless-specialist` (usan la CLI de 0ctopus).
- **60 especialistas avanzados**: web/API, auth, mobile, streaming, cloud/contenedores, red, Active Directory, wireless/RF/IoT, OSINT, reversing y cripto. Catálogo en `.claude/agents/README.md`.
- **Redactor**: `report-writer` consolida los hallazgos en `output/`.
- **Skills** (`.claude/skills/`): `recon`, `web-audit`, `network-scan`, `wifi-audit`, `mobile-audit`, `cloud-audit`, `streaming-audit`, `reporting`.

**Ejemplo:** pedile a Claude *"auditá la seguridad de underc0de.org"* y el orquestador coordina recon → web/red → reporte, dejando todo en `output/`.

> ⚠️ Usar **solo contra objetivos autorizados**. Ver `CLAUDE.md` para las reglas de alcance y autorización.

---

## 🤝 Contribuyendo

1. Hacer fork del proyecto.
2. Crear una rama (`git checkout -b feature/nueva-herramienta`).
3. Realizar cambios y probar.
4. Abrir un Pull Request describiendo la funcionalidad.

---

## 📄 Licencia

Este proyecto está bajo licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

> Desarrollado por Underc0de.
