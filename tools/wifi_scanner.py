#!/usr/bin/env python3
# Archivo: tools/wifi_scanner.py

import os
import click
import random
import time
from datetime import datetime

# Intentamos importar PyWiFi y constantes
try:
    from pywifi import PyWiFi
    import pywifi.const as wifi_const
except ImportError:
    raise click.ClickException(
        "❌ Módulo `pywifi` no encontrado. Instálalo con `pip install pywifi comtypes`."
    )

# User‑Agents ASCII para rotar
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

# Mapeos de autenticación (AKM) y cifrado
AKM_MAPPING = {
    wifi_const.AKM_TYPE_NONE: 'NONE',
    wifi_const.AKM_TYPE_WPA: 'WPA',
    wifi_const.AKM_TYPE_WPAPSK: 'WPA-PSK',
    wifi_const.AKM_TYPE_WPA2PSK: 'WPA2-PSK',
}
CIPHER_MAPPING = {
    wifi_const.CIPHER_TYPE_NONE: 'NONE',
    wifi_const.CIPHER_TYPE_WEP: 'WEP',
    wifi_const.CIPHER_TYPE_TKIP: 'TKIP',
    wifi_const.CIPHER_TYPE_CCMP: 'CCMP',
}

@click.command(name='wifi-scan')
def cmd_wifi_scan():
    """Escanea redes WiFi cercanas, muestra tabla y genera TXT con resultados."""
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    if not interfaces:
        raise click.ClickException('No se detectaron interfaces WiFi.')

    # Mostrar interfaces disponibles
    click.echo('📶 Interfaces WiFi disponibles:')
    for idx, intf in enumerate(interfaces):
        click.echo(f"  [{idx}] {intf.name()}")

    # Selección de interfaz
    iface = click.prompt('Selecciona índice de interfaz', type=int)
    if iface < 0 or iface >= len(interfaces):
        raise click.ClickException(f'Interfaz inválida: {iface}')
    interface = interfaces[iface]

    # Preguntar duración de escaneo
    timeout = click.prompt('¿Cuántos segundos quieres escanear?', default=5, type=int)
    click.echo(f"🔍 Escaneando en {interface.name()} por {timeout}s...")
    interface.scan()
    time.sleep(timeout)
    raw_results = interface.scan_results()

    # Eliminar duplicados: por SSID si existe, o por BSSID si SSID vacío
    unique = {}
    for net in raw_results:
        ssid = net.ssid or ''
        key = ssid.lower() if ssid else net.bssid
        prev = unique.get(key)
        if prev is None or net.signal > prev.signal:
            unique[key] = net
    results = list(unique.values())

    # Formateo de redes
    networks = []
    for net in results:
        auth = ','.join(AKM_MAPPING.get(a, str(a)) for a in net.akm)
        cipher = CIPHER_MAPPING.get(net.cipher, str(net.cipher))
        networks.append({
            'ssid': net.ssid or '<Oculto>',
            'bssid': net.bssid,
            'signal_dbm': net.signal,
            'signal': f"{net.signal} dBm",
            'auth': auth,
            'cipher': cipher
        })
    # Ordenar por señal
    networks.sort(key=lambda x: x['signal_dbm'], reverse=True)

    # Definir campos y cabeceras
    fields = [
        ('ssid', 'SSID'),
        ('bssid', 'BSSID'),
        ('signal', 'Señal(dBm)'),
        ('auth', 'Auth'),
        ('cipher', 'Cipher')
    ]
    # Calcular anchos de columna
    widths = {}
    for key, header in fields:
        max_content = max(len(str(n[key])) for n in networks) if networks else 0
        widths[header] = max(len(header), max_content)

    # Construir filas de cabecera y separador
    header_row = ' │ '.join(f"{header:{widths[header]}}" for _, header in fields)
    sep_row = '─┼─'.join('─' * widths[header] for _, header in fields)

    # Mostrar tabla
    click.echo('📡 Redes encontradas:')
    click.echo(f"🔸 {header_row}")
    click.echo(f"🔸 {sep_row}")
    for n in networks:
        row = ' │ '.join(f"{str(n[key]):{widths[header]}}" for key, header in fields)
        click.echo(f"   {row}")

    # Guardar TXT en output (siempre mismo archivo)
    os.makedirs('output', exist_ok=True)
    txt_path = os.path.join('output', 'wifi_scan.txt')
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(f"Redes WiFi escaneadas - {datetime.now()}\n")
        f.write(f"Interfaz: {interface.name()}\n\n")
        f.write(header_row + '\n')
        f.write(sep_row + '\n')
        for n in networks:
            f.write(' │ '.join(f"{str(n[key]):{widths[header]}}" for key, header in fields) + '\n')
    click.echo(click.style(f"✅ Resultados guardados en {txt_path}", fg='green'))

if __name__ == '__main__':
    cmd_wifi_scan()
