import os
import platform
import click
from io import BytesIO
from datetime import datetime
from typing import Optional, Union

from scapy.all import sniff, conf
from scapy.utils import PcapWriter

# Configuración por defecto
DEFAULT_INTERFACE = None  # None = todas las interfaces
DEFAULT_COUNT     = 0     # 0 = ilimitado (se detiene por timeout)
DEFAULT_TIMEOUT   = 10    # segundos

# En Windows, forzamos que Scapy use sockets de capa 3
if platform.system() == "Windows":
    conf.L2socket = conf.L3socket


def sniff_packets(
    interface: Optional[str] = DEFAULT_INTERFACE,
    count: int               = DEFAULT_COUNT,
    timeout: int             = DEFAULT_TIMEOUT
) -> bytes:
    """
    Captura paquetes de red y devuelve los datos en formato PCAP.

    Parámetros:
      interface: Nombre de la interfaz a capturar (por defecto todas)
      count:     Número máximo de paquetes (0 = ilimitado hasta timeout)
      timeout:   Duración de captura en segundos

    Retorna:
      Bytes del archivo PCAP generado.
    """
    print(f"[+] Iniciando captura: iface={interface or 'any'}, count={count or 'inf'}, timeout={timeout}s")
    try:
        packets = sniff(
            iface=interface,
            count=count,
            timeout=timeout,
            L2socket=conf.L3socket
        )
    except OSError:
        raise click.ClickException(
            "\n[!] No se pudo iniciar la captura de paquetes. Asegurate de:\n"
            "  - Instalar Npcap en Windows (modo WinPcap compatible).\n"
            "  - Ejecutar la terminal como Administrador.\n"
        )

    # Escribir paquetes en buffer usando PcapWriter (no cierra el buffer)
    buf = BytesIO()
    writer = PcapWriter(buf, sync=True)
    for pkt in packets:
        writer.write(pkt)
    buf.seek(0)
    return buf.read()


def save_pcap(
    data: Union[bytes, bytearray],
    output_dir: str = "output"
) -> str:
    """
    Guarda los datos PCAP en un archivo dentro de output_dir y devuelve la ruta.

    Parámetros:
      data: Bytes o bytearray con el contenido del pcap
      output_dir: Carpeta donde guardar el archivo

    Retorna:
      Ruta del archivo PCAP generado.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"packets_{ts}.pcap"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "wb") as f:
        f.write(data)

    return filepath
