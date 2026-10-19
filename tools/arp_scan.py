# Archivo: tools/arp_scan.py

import os
import socket
import platform
import ipaddress
import click
from datetime import datetime

from scapy.all import ARP, Ether, srp, conf


def get_local_cidr() -> str:
    """
    Intenta deducir la red local (CIDR /24) a partir de la IP del host.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(net)


def arp_scan(network: str, timeout: int = 3) -> list[dict]:
    """
    Realiza un ARP scan sobre el rango indicado.

    Retorna una lista de dicts con 'ip' y 'mac' de los hosts que responden.
    """
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    hosts = []
    for _, received in answered:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts


@click.command(name='arp-scan')
@click.option('--network', default=None, help='Rango CIDR (ej: 192.168.1.0/24). Auto si se omite.')
@click.option('--timeout', default=3, type=int, help='Tiempo de espera por respuesta (s)')
def cmd_arp_scan(network, timeout):
    """Descubre hosts en la red local mediante ARP."""
    if not network:
        try:
            network = get_local_cidr()
        except Exception as e:
            raise click.ClickException(f"❌ No se pudo deducir la red local: {e}")

    click.echo(f"📡  ARP scan sobre: {click.style(network, fg='cyan')} (timeout {timeout}s)\n")

    try:
        hosts = arp_scan(network, timeout=timeout)
    except OSError:
        raise click.ClickException(
            "\n[!] No se pudo enviar el ARP scan. Asegurate de:\n"
            "  - Instalar Npcap en Windows (modo WinPcap compatible).\n"
            "  - Ejecutar la terminal como Administrador.\n"
        )
    except Exception as e:
        raise click.ClickException(f"❌ Error durante el escaneo: {e}")

    if not hosts:
        click.echo(click.style("No se detectaron hosts.", fg='yellow'))
        return

    click.echo(click.style(f"{'IP':<18} MAC", bold=True))
    click.echo('-' * 40)
    for h in hosts:
        click.echo(click.style(f"{h['ip']:<18} {h['mac']}", fg='green'))

    # Guardar reporte
    os.makedirs('output', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join('output', f'arp_scan-{ts}.txt')
    header = [
        'ARP SCAN',
        f'Red: {network}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Hosts: {len(hosts)}',
        '',
        f"{'IP':<18} MAC",
        '-' * 40,
    ]
    rows = [f"{h['ip']:<18} {h['mac']}" for h in hosts]
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + rows))

    click.echo(click.style(f"\n✅ {len(hosts)} hosts guardados en: {filepath}", fg='green', bold=True))

    # Reporte HTML
    from tools import report
    html_path = report.save(
        tool='arp-scan', title='Descubrimiento de hosts (ARP)', target=network,
        stats=[report.stat('Hosts vivos', len(hosts), 'ok'),
               report.stat('Red', network, 'info')],
        sections=[report.table('Hosts detectados', ['IP', 'MAC'],
                               [[h['ip'], h['mac']] for h in hosts])],
    )
    click.echo(click.style(f"📄 Reporte HTML: {html_path}", fg='green', bold=True))


if __name__ == '__main__':
    cmd_arp_scan()
