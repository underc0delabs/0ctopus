# Instalación

## Requisitos

- **Python 3.10+** (probado en 3.14).
- `pip` y, recomendado, un entorno virtual.
- **Windows**: para captura de paquetes / `arp-scan` / WiFi, instalar [Npcap](https://nmap.org/npcap) en modo *"WinPcap Compatible"* y ejecutar la terminal **como Administrador**.
- **Opcional**: `hashcat` (para `wifi-crack`), `nmap` (algunos flujos), adaptador WiFi con modo monitor (para WiFi).

## Pasos

```bash
# 1) Clonar
git clone https://github.com/underc0delabs/0ctopus.git
cd 0ctopus

# 2) Entorno virtual (recomendado)
python -m venv env
source env/bin/activate        # Linux/macOS
env\Scripts\activate           # Windows

# 3) Dependencias
pip install -r requirements.txt
```

## Dependencias principales

`requests`, `urllib3`, `certifi`, `scapy`, `dnspython`, `python-nmap`, `click`, `colorama`,
`pyfiglet`, `beautifulsoup4`, `python-whois`, `pywifi`, `comtypes`, `pyhashcat`.

> El archivo `requirements.txt` está en **UTF-8** y con versiones fijadas. Si `pip` falla, verificá que tu Python sea 3.10+.

## Verificación

```bash
python 0ctopus.py --help
python 0ctopus.py hash-identify 5f4dcc3b5aa765d61d8327deb882cf99
```

Si ves el banner y la ayuda de comandos, está listo. Los reportes se generan en `output/`.

## Uso con Claude Code (capa agéntica)

La carpeta `.claude/` trae agentes y skills. Abrí el proyecto con Claude Code y pedí, por ejemplo, *"auditá la seguridad de underc0de.org"*. Ver [agents.md](agents.md).
