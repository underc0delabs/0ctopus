---
name: network-scan
description: Análisis de seguridad de red con 0ctopus — escaneo de puertos y servicios, descubrimiento de hosts en la LAN por ARP y captura de tráfico a PCAP. Usar para evaluar la capa de red de un objetivo o una red interna autorizada.
---

# Skill: Análisis de Red (0ctopus)

Guía para evaluar la capa de red. Ejecutar desde la raíz: `python 0ctopus.py <comando>`.

## ⚠️ Alcance y requisitos
- Actividades activas: solo contra objetivos/redes autorizados.
- `arp-scan` y `sniff-packets` requieren privilegios (admin/root) y, en Windows, **Npcap** (modo "WinPcap Compatible").

## Herramientas

### scan-ports
```bash
python 0ctopus.py scan-ports --host <host>
```
Escanea puertos comunes, detecta estado (abierto/filtrado), servicio y versión (banner / cabecera Server). Sin `--host` usa `config.py`.

### arp-scan
```bash
python 0ctopus.py arp-scan [--network 192.168.1.0/24] [--timeout 3]
```
Descubre hosts vivos en la LAN (IP + MAC). Sin `--network` autodetecta la red local /24.

### sniff-packets
```bash
python 0ctopus.py sniff-packets [--interface IF] [--count N] [--timeout S]
```
Captura tráfico y lo guarda en `output/packets-*.pcap`.

## Metodología

1. `scan-ports --host` como base del análisis de servicios.
2. En red interna autorizada, `arp-scan` para inventario de hosts.
3. `sniff-packets` solo si se solicita y hay privilegios.

## Interpretación → severidad

- Puertos administrativos expuestos a Internet (22, 3389, 3306, 5432, etc.) → **Media/Alta**.
- Servicios con versión antigua/vulnerable → **Alta/Media** según CVE.
- Protocolos en claro (FTP 21, Telnet 23, HTTP 80 sin redirección) → **Media**.
- Gran cantidad de puertos abiertos → revisar superficie.

Cada comando deja su HTML en `output/reports/`. Si falla por privilegios/Npcap, reportalo en vez de inventar resultados.
