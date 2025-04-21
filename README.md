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
| `dirb`               | Crawling de directorios internos (`output/dirb_scan-<HOST>.txt`)
|                      | - `--max-depth N` Profundidad máxima (por defecto 2)             |
|                      | - `--verbose`     Muestra progreso en consola                   |
| `sniff-packets`      | Captura paquetes de red en `.pcap` (`output/packets-<HOST>.pcap`)|

**Ejemplo:**
```bash
python 0ctopus.py dirb --max-depth 3 --verbose
```

---

## 📂 Salida

Todos los resultados se guardan en la carpeta `output/`. Los nombres de archivo incluyen el comando y el `HOST` configurado.

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
