# tools/wifi_handshake.py

import os
import sys
import click
from colorama import init, Fore
from scapy.all import sniff, wrpcap, conf
from datetime import datetime

# Inicializa colorama
init(autoreset=True)

# Archivo fijo de salida (se sobrescribe)
OUTPUT_FILE = os.path.join('output', 'wifi_handshake.pcap')

@click.command(name='wifi-handshake')
def cmd_wifi_handshake():
    """
    Captura el 4‑way handshake WPA/WPA2 en modo monitor.
    """
    # Import dinámico para que falle limpio si falta pywifi
    try:
        from pywifi import PyWiFi
    except ImportError:
        raise click.ClickException(
            "❌ No se encontró `pywifi`. Instálalo con:\n"
            "    pip install pywifi comtypes"
        )

    wifi = PyWiFi()
    ifaces = wifi.interfaces()
    if not ifaces:
        raise click.ClickException("❌ No se detectaron interfaces Wi‑Fi. Asegúrate de tener al menos una.")

    click.echo(Fore.CYAN + "📶 Interfaces en modo monitor disponibles:")
    for idx, iface in enumerate(ifaces):
        click.echo(f"  [{idx}] {iface.name()}")

    # Elección de interfaz
    idx = click.prompt(Fore.MAGENTA + "Selecciona índice de interfaz para monitor mode", type=int, default=0)
    try:
        iface_name = ifaces[idx].name()
    except IndexError:
        raise click.ClickException("❌ Índice de interfaz inválido.")

    # Duración de la captura
    timeout = click.prompt(Fore.MAGENTA + "Duración de captura (segundos)", type=int, default=30)

    click.echo(Fore.YELLOW + f"🔒 Capturando handshake en {iface_name} durante {timeout}s...")
    os.makedirs('output', exist_ok=True)

    # Fallback de socket L2 en Windows
    if sys.platform.startswith('win'):
        # Forzar capa 3 no sirve para handshakes 802.11
        # Solo informar al usuario
        raise click.ClickException(
            "❌ En Windows no se puede capturar el handshake sin Npcap en modo monitor.\n"
            "   1) Instala Npcap (https://nmap.org/npcap) en modo “WinPcap Compatible”.\n"
            "   2) Ejecuta la terminal como Administrador.\n"
            "   3) Asegúrate de que la interfaz esté en modo monitor.\n"
            "O bien usa Linux y ejecuta con sudo sobre tu interfaz en modo monitor."
        )

    # Función filtro para EAPOL (handshake)
    def is_eapol(pkt):
        return pkt.haslayer('EAPOL')

    try:
        # Intentar sniff de capa 2
        packets = sniff(iface=iface_name, timeout=timeout, lfilter=is_eapol)
    except RuntimeError as e:
        # Error típico de WinPcap/Npcap faltante
        raise click.ClickException(
            "❌ No se pudo abrir el socket de capa 2: “winpcap is not installed”.\n"
            "   Instala Npcap y ejecuta como administrador, o usa Linux con modo monitor.\n"
            f"   Detalle técnico: {e}"
        )

    if not packets:
        click.echo(Fore.RED + "❌ No se detectó ningún paquete EAPOL (handshake).")
        sys.exit(1)

    # Guardar handshake en archivo .pcap
    wrpcap(OUTPUT_FILE, packets)
    click.echo(Fore.GREEN + f"✅ Handshake capturado y guardado en: {OUTPUT_FILE}")
