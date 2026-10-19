#!/usr/bin/env python3
# Archivo: 0ctopus.py

import os
import sys
import subprocess
import click
from colorama import init, Fore, Style
from datetime import datetime
from config import HOST, URL_BASE

from tools.portscanner import scan as portscan
from tools.dirb import crawl_links
from tools.subdomain_enum import enumerate as enum_subdomains_tool
from tools.vuln_check import check as vuln_check
from tools.packet_sniffer import sniff_packets, save_pcap
from tools.ip_geolocator import cmd_geoip
from tools.whois_lookup import cmd_whois
from tools.admin_finder import cmd_find_admin
from tools.wifi_scanner import cmd_wifi_scan
from tools.wifi_handshake import cmd_wifi_handshake
from tools.handshake_crack import cmd_wifi_crack
from tools.dns_recon import cmd_dns_recon
from tools.header_analyzer import cmd_header_analyzer
from tools.hash_identify import cmd_hash_identify
from tools.wayback_urls import cmd_wayback
from tools.arp_scan import cmd_arp_scan
from tools import report

# Inicializa colorama
def init_color():
    init(autoreset=True)

# Banner ASCII
BANNER = r"""
 ██████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
██╔═████╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
██║██╔██║██║        ██║   ██║   ██║██████╔╝██║   ██║███████╗
████╔╝██║██║        ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║
╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
 ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
          Underc0de Hacking Tool
"""

@click.group()
def cli():
    """0ctopus: Navaja Suiza de seguridad informática"""
    init_color()
    click.echo(Fore.GREEN + BANNER)

# Registrar todos los comandos
cli.add_command(cmd_geoip, name='geoip')
cli.add_command(cmd_whois, name='whois')
cli.add_command(cmd_find_admin, name='find-admin')
cli.add_command(cmd_wifi_scan, name='wifi-scan')
cli.add_command(cmd_wifi_handshake, name='wifi-handshake')
cli.add_command(cmd_wifi_crack, name='wifi-crack')
cli.add_command(cmd_dns_recon, name='dns-recon')
cli.add_command(cmd_header_analyzer, name='header-analyzer')
cli.add_command(cmd_hash_identify, name='hash-identify')
cli.add_command(cmd_wayback, name='wayback-urls')
cli.add_command(cmd_arp_scan, name='arp-scan')

@cli.command(name='scan-ports')
@click.option('--host', 'target_host', default=None, help='Host objetivo (por defecto config.py)')
def scan_ports(target_host):
    """Escaneo avanzado de puertos con detección de servicios y guarda resultado en /output"""
    target_host = target_host or HOST
    resultados = portscan(common=True, host=target_host)
    abiertos   = [r for r in resultados if r['state']=='open']
    filtrados  = [r for r in resultados if r['state']=='filtered']

    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'port_scan-{target_host}.txt')
    header = [
        'ESCANEO DE PUERTOS AVANZADO',
        f'Target: {target_host}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Total: {len(resultados)}  Abiertos: {len(abiertos)}  Filtrados: {len(filtrados)}',
        ''
    ]
    table = [f"{'Puerto':<8} {'Estado':<10} {'Servicio':<20} Versión", '-'*60]
    for item in resultados:
        port    = f"{item['port']:<8}"
        state   = 'ABIERTO' if item['state']=='open' else 'FILTRADO'
        service = f"{item['service'] or '-':<20}"
        version = item['version'] or '-'
        table.append(f"{port} {state:<10} {service} {version}")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + table))

    click.echo(Fore.CYAN + '\n' + '═'*60)
    click.echo(Fore.YELLOW + '🔥 ESCANEO DE PUERTOS AVANZADO'.center(60))
    click.echo(Fore.CYAN + '═'*60)
    click.echo(Fore.GREEN + header[1])
    click.echo(Fore.BLUE + header[2])
    click.echo(Fore.MAGENTA + header[3] + '\n')
    click.echo(Fore.CYAN + table[0])
    click.echo(Fore.WHITE + table[1])
    for row in table[2:]:
        color = Fore.GREEN if 'ABIERTO' in row else Fore.YELLOW
        click.echo(color + row)
    click.echo()

    # Reporte HTML
    rows_html = [[
        item['port'],
        'ABIERTO' if item['state'] == 'open' else 'FILTRADO',
        item['service'] or '-',
        item['version'] or '-',
    ] for item in resultados]
    html_path = report.save(
        tool='scan-ports', title='Escaneo de puertos avanzado', target=target_host,
        stats=[report.stat('Total', len(resultados)),
               report.stat('Abiertos', len(abiertos), 'ok'),
               report.stat('Filtrados', len(filtrados), 'warn')],
        sections=[report.table('Puertos detectados',
                               ['Puerto', 'Estado', 'Servicio', 'Versión'],
                               rows_html, status_col=1)],
    )
    click.echo(Fore.GREEN + f"📄 Reporte HTML: {html_path}")

@cli.command(name='vuln-check')
@click.option('--url', 'target_url', default=None, help='URL objetivo (por defecto config.py)')
def vuln_check_cmd(target_url):
    """Chequeo rápido de vulnerabilidades en HOST y sus subdominios; guarda resultado en /output"""
    target_url = target_url or URL_BASE
    target_name = target_url.replace('https://', '').replace('http://', '').strip('/')
    report_text = vuln_check(target_url)
    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'vuln_check-{target_name}.txt')
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report_text)
    click.echo(report_text)

    # Reporte HTML
    html_path = report.save(
        tool='vuln-check', title='Chequeo de vulnerabilidades', target=target_name,
        stats=[report.stat('Objetivo', target_name, 'info')],
        sections=[report.text('Resultado del chequeo', report_text)],
    )
    click.echo(Fore.GREEN + f"📄 Reporte HTML: {html_path}")

@cli.command(name='enum-subdomains')
@click.option('--domain', 'target_domain', default=None, help='Dominio objetivo (por defecto config.py)')
def cmd_enum_subdomains(target_domain):
    """Enumera subdominios de HOST definido en config.py y guarda resultado en /output"""
    target_domain = target_domain or HOST
    encontrados = enum_subdomains_tool(domain=target_domain)
    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'subdomains-{target_domain}.txt')
    header = [
        'ENUMERACIÓN DE SUBDOMINIOS',
        f'Target: {target_domain}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Total: {len(encontrados)}',
        ''
    ]
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + encontrados))

    click.echo(Fore.CYAN + '\n' + '═'*60)
    click.echo(Fore.YELLOW + '🔍 ENUMERACIÓN DE SUBDOMINIOS'.center(60))
    click.echo(Fore.CYAN + '═'*60)
    click.echo(Fore.GREEN + header[1])
    click.echo(Fore.BLUE + header[2] + '\n')
    for sub in encontrados:
        click.echo(Fore.CYAN + f"- {sub}")
    click.echo()

    # Reporte HTML
    html_path = report.save(
        tool='enum-subdomains', title='Enumeración de subdominios', target=target_domain,
        stats=[report.stat('Subdominios', len(encontrados), 'ok')],
        sections=[report.listing('Subdominios encontrados', encontrados)],
    )
    click.echo(Fore.GREEN + f"📄 Reporte HTML: {html_path}")

@cli.command(name='dirb')
@click.option('--url', 'target_url', default=None, help='URL objetivo (por defecto config.py)')
@click.option('--max-depth', default=2, help='Profundidad máxima de crawling')
@click.option('--verbose', is_flag=True, help='Mostrar detalles en consola')
def dirb(target_url, max_depth, verbose):
    """Crawling de directorios internos y guarda resultado en /output"""
    target_url = target_url or URL_BASE
    target_name = target_url.replace('https://', '').replace('http://', '').strip('/')
    results = crawl_links(target_url, max_depth=max_depth, verbose=verbose)
    max_len  = max((len(p) for p,_ in results), default=len('Path'))
    col_w    = max(max_len, len('Path')) + 2

    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'dirb_scan-{target_name}.txt')
    header = [
        'CRAWLING DE DIRECTORIOS AVANZADO',
        f'Target: {target_name}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Total: {len(results)}',
        ''
    ]
    rows = [f"{p:<{col_w}} {s}" for p,s in results]
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + rows))

    click.echo(Fore.CYAN + '\n' + '═'*(col_w+8))
    click.echo(Fore.YELLOW + '🔥 CRAWLING DE DIRECTORIOS AVANZADO'.center(col_w+8))
    click.echo(Fore.CYAN + '═'*(col_w+8))
    click.echo(Fore.CYAN + f"{'Path':<{col_w}} Status")
    click.echo(Fore.WHITE + '-'*(col_w+len(' Status')))
    for p,s in results:
        color = Fore.GREEN if s<400 else Fore.RED
        click.echo(color + f"{p:<{col_w}} {s}")
    click.echo()

    # Reporte HTML
    ok = sum(1 for _, s in results if s < 400)
    err = len(results) - ok
    html_path = report.save(
        tool='dirb', title='Crawling de directorios', target=target_name,
        stats=[report.stat('Rutas', len(results)),
               report.stat('OK (<400)', ok, 'ok'),
               report.stat('Errores', err, 'bad')],
        sections=[report.table('Rutas encontradas', ['Path', 'Status'],
                               [[p, s] for p, s in results], status_col=1)],
    )
    click.echo(Fore.GREEN + f"📄 Reporte HTML: {html_path}")

@cli.command(name='sniff-packets')
@click.option('--interface', default=None, help='Interfaz a capturar')
@click.option('--count', default=0, type=int, help='Número de paquetes (0=ilimitado)')
@click.option('--timeout', default=10, type=int, help='Tiempo de captura en segundos')
def sniff_packets_cmd(interface, count, timeout):
    """Captura paquetes de red y guarda PCAP en /output"""
    data     = sniff_packets(interface=interface, count=count, timeout=timeout)
    filepath = save_pcap(data)
    click.echo(Fore.GREEN + f"Paquetes capturados en {filepath}")

    # Reporte HTML
    html_path = report.save(
        tool='sniff-packets', title='Captura de paquetes de red', target=HOST,
        stats=[report.stat('Bytes PCAP', len(data), 'info'),
               report.stat('Interfaz', interface or 'any', 'muted'),
               report.stat('Timeout', f'{timeout}s', 'muted')],
        sections=[report.keyvalue('Detalles de la captura', {
            'Archivo PCAP': filepath,
            'Interfaz': interface or 'todas',
            'Límite de paquetes': count or 'ilimitado',
            'Duración': f'{timeout}s',
            'Tamaño': f'{len(data)} bytes',
        })],
    )
    click.echo(Fore.GREEN + f"📄 Reporte HTML: {html_path}")

@cli.command(name='report-build')
@click.argument('json_file', type=click.Path(exists=True))
def report_build_cmd(json_file):
    """Construye un reporte HTML consolidado desde un archivo JSON (uso agéntico)."""
    html_path = report.build_from_json(json_file)
    click.echo(Fore.GREEN + f"📄 Reporte HTML generado: {html_path}")

@cli.command(name='rebuild-index')
def rebuild_index_cmd():
    """Regenera el dashboard output/index.html desde el manifiesto."""
    path = report.rebuild_index()
    click.echo(Fore.GREEN + f"📊 Dashboard regenerado: {path}")

def show_menu():
    init_color()
    click.echo(Fore.GREEN + BANNER)
    options = [
        ('1', 'scan-ports'),
        ('2', 'vuln-check'),
        ('3', 'enum-subdomains'),
        ('4', 'dirb'),
        ('5', 'sniff-packets'),
        ('6', 'geoip'),
        ('7', 'whois'),
        ('8', 'find-admin'),
        ('9', 'wifi-scan'),
        ('10','wifi-handshake'),
        ('11','wifi-crack'),
        ('12','dns-recon'),
        ('13','header-analyzer'),
        ('14','hash-identify'),
        ('15','wayback-urls'),
        ('16','arp-scan'),
        ('0', 'Salir'),
    ]
    click.echo(Fore.CYAN + "Menú de herramientas disponibles:")
    for key, cmd in options:
        click.echo(Fore.YELLOW + f"  {key}. {cmd}")
    choice = click.prompt(Fore.MAGENTA + "Selecciona una opción", default='0')

    if choice == '0':
        sys.exit(0)

    mapping = {k: cmd for k, cmd in options}
    cmd = mapping.get(choice)
    if not cmd:
        click.echo(Fore.RED + "Opción inválida. Saliendo.")
        sys.exit(1)

    # ejecución según comando
    if cmd in ('geoip', 'whois', 'find-admin', 'hash-identify', 'dns-recon',
               'header-analyzer', 'wayback-urls'):
        prompts = {
            'geoip': "Ingresa la IP a geolocalizar",
            'whois': "Ingresa el dominio para WHOIS",
            'find-admin': "Ingresa la URL base (ej: https://site.com)",
            'hash-identify': "Ingresa el hash a identificar",
            'dns-recon': "Ingresa el dominio (vacío = config.py)",
            'header-analyzer': "Ingresa la URL (vacío = config.py)",
            'wayback-urls': "Ingresa el dominio (vacío = config.py)",
        }
        # Los que admiten valor por defecto desde config.py permiten entrada vacía
        optional = cmd in ('dns-recon', 'header-analyzer', 'wayback-urls')
        arg = click.prompt(Fore.MAGENTA + prompts[cmd], default='' if optional else None,
                           show_default=False)
        args = [cmd, arg] if arg else [cmd]
        subprocess.call([sys.executable, sys.argv[0], *args])

    elif cmd in ('wifi-scan', 'wifi-handshake', 'wifi-crack', 'arp-scan'):
        subprocess.call([sys.executable, sys.argv[0], cmd])

    else:
        subprocess.call([sys.executable, sys.argv[0], cmd])

if __name__ == '__main__':
    if len(sys.argv) == 1:
        show_menu()
    else:
        cli()
