# Preguntas frecuentes (FAQ)

### ¿Qué es 0ctopus?
Una navaja suiza de pentesting de Underc0de: CLI en Python + reportes HTML + capa agéntica (300+ agentes) para Claude.

### ¿Necesito Claude para usarlo?
No. La CLI funciona sola (`python 0ctopus.py ...`). La capa agéntica `.claude/` es un **extra** para orquestar evaluaciones con Claude Code.

### ¿Dónde quedan los resultados?
En `output/`: un dashboard `index.html` y un HTML por reporte en `reports/`, más archivos TXT/JSON/PCAP. Está en `.gitignore`.

### ¿Puedo apuntar a cualquier dominio?
Solo a objetivos **autorizados**. Ver [security.md](security.md). El objetivo por defecto es el de `config.py`.

### `pip install -r requirements.txt` falla
Verificá Python 3.10+ y que el archivo esté en UTF-8 (lo está). En Windows, algunas libs de red necesitan Npcap.

### `arp-scan` / `sniff-packets` / `wifi-*` no funcionan
Requieren privilegios (admin/root) y, en Windows, **Npcap** (modo WinPcap). Las de WiFi además necesitan hardware con modo monitor y son interactivas.

### Veo errores de emojis en la consola (Windows)
La consola clásica `cmd.exe` usa cp1252. Usá Windows Terminal (UTF-8) o establecé `PYTHONIOENCODING=utf-8`.

### ¿Cómo agrego una herramienta o un agente?
Herramienta: ver [tools.md](tools.md). Agente: creá un `.md` en `.claude/agents/` con frontmatter `name`/`description`/`tools`/`model` y su metodología.

### ¿Cómo genero un reporte consolidado?
`python 0ctopus.py report-build output/engagement.json` (ver [reporting.md](reporting.md)). O dejá que el agente `report-writer` lo haga.

### ¿Hay documentación offline / para imprimir?
Sí: `0ctopus-cheatsheet.pdf` en esta carpeta, y el portal `index.html`.
