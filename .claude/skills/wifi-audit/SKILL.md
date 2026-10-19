---
name: wifi-audit
description: Auditoría de redes WiFi con 0ctopus — escaneo de redes cercanas, captura de handshakes WPA/WPA2, cracking con hashcat e identificación de hashes. Usar solo para auditoría wireless autorizada con hardware compatible.
---

# Skill: Auditoría WiFi (0ctopus)

Guía para auditar redes inalámbricas. Ejecutar desde la raíz: `python 0ctopus.py <comando>`.

## ⚠️ Alcance y requisitos
- Solo contra redes **propias o con autorización explícita**. Capturar/crackear redes ajenas es ilegal.
- Requiere adaptador WiFi compatible, modo monitor y privilegios. En Windows, Npcap.
- `wifi-scan`, `wifi-handshake` y `wifi-crack` son **interactivos** (piden interfaz, duración, diccionario/charset). Si no se pueden responder prompts de forma autónoma, pedir al usuario que las ejecute o que confirme parámetros.

## Herramientas

### wifi-scan *(interactivo)*
```bash
python 0ctopus.py wifi-scan
```
Lista redes: SSID, BSSID, señal (dBm), auth (WPA/WPA2/NONE), cipher (CCMP/TKIP/WEP).

### wifi-handshake *(interactivo, requiere monitor)*
```bash
python 0ctopus.py wifi-handshake
```
Captura el 4-way handshake WPA/WPA2 → `output/wifi_handshake.pcap`.

### wifi-crack *(interactivo, requiere hashcat)*
```bash
python 0ctopus.py wifi-crack
```
Crackea un handshake con hashcat por diccionario o fuerza bruta (máscara).

### hash-identify *(no interactivo)*
```bash
python 0ctopus.py hash-identify <hash>
```
Identifica el tipo probable de un hash por formato (MD5, SHA, bcrypt, NTLM, WPA, etc.).

## Metodología

1. `wifi-scan` → inventario y detección de redes abiertas/WEP/WPA.
2. Con autorización: `wifi-handshake` → captura; luego `wifi-crack`.
3. `hash-identify` para clasificar hashes antes de crackear.

## Interpretación → severidad

- Red abierta (auth NONE) → **Alta**.
- WEP o WPA (TKIP) → **Alta/Media** (cifrado obsoleto).
- WPA2-PSK con clave débil crackeada → **Alta**.
- WPA2/WPA3 con clave fuerte → aceptable.

Cada comando deja su HTML en `output/reports/`. No expongas credenciales de terceros ni simules resultados si falta hardware.
