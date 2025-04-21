# 0ctopus

Navaja suiza de seguridad informática — Herramienta de línea de comandos todo en uno.

## Requisitos

- Python 3.10 o superior
- pip
- (Opcional) **nmap** instalado en el sistema para detección de servicio y versión

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/usuario/0ctopus.git
cd 0ctopus

# Crear y activar entorno virtual
# Windows:
python -m venv env
env\Scripts\activate

# macOS / Linux:
python3 -m venv env
source env/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

Mostrar ayuda global y listar comandos:

```bash
python 0ctopus.py --help
```

### Comandos principales

- **scan-ports**  
  Escanea puertos comunes en `HOST` con detección de servicio y versión. Genera (o reemplaza) el archivo `output/port_scan-<HOST>.txt`.
  ```bash
  python 0ctopus.py scan-ports
  ```

- **enum-subdomains**  
  Enumera subdominios de `HOST` usando una lista (`wordlist`).
  ```bash
  python 0ctopus.py enum-subdomains --wordlist subdomains.txt
  ```

- **dirb-scan**  
  Fuerza bruta de rutas en `URL_BASE` usando una lista de paths.
  ```bash
  python 0ctopus.py dirb-scan --wordlist paths.txt
  ```

- **vuln-check**  
  Chequeo rápido de vulnerabilidades (headers, SSL, HTTPS) en `URL_BASE`.
  ```bash
  python 0ctopus.py vuln-check
  ```

- **sniff**  
  Captura paquetes en una interfaz de red. Ejemplo: capturar 10 paquetes en `eth0`.
  ```bash
  python 0ctopus.py sniff --interface eth0 --count 10
  ```

## Archivo .gitignore

```gitignore
env/
__pycache__/
*.py[cod]
output/
```

## Licencia

Este proyecto está bajo licencia MIT.

