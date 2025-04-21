# tools/packet_sniffer.py

from scapy.all import sniff
from config import HOST  # importado por consistencia, aunque no se use directamente

def sniff_packets(interface: str, count: int = 0) -> list[str]:
    """
    Captura paquetes en 'interface'. Si count=0, captura hasta Ctrl+C.
    Devuelve resúmenes de los paquetes capturados.
    """
    paquetes = []

    def procesar(pkt):
        paquetes.append(pkt.summary())

    sniff(iface=interface, prn=procesar, count=count)
    return paquetes
