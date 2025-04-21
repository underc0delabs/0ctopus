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

# Inicializa colorama
def init_color():
    init(autoreset=True)

# Banner ASCII estático
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

# Registrar comandos externos
cli.add_command(cmd_geoip)
cli.add_command(cmd_whois)

@cli.command(name='scan-ports')
def scan_ports():
    """Escaneo avanzado de puertos con detección de servicios y guarda resultado en /output"""
    resultados = portscan(common=True)
    abiertos = [r for r in resultados if r['state'] == 'open']
    filtrados = [r for r in resultados if r['state'] == 'filtered']

    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'port_scan-{HOST}.txt')
    header = [
        'ESCANEO DE PUERTOS AVANZADO',
        f'Target: {HOST}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Total: {len(resultados)}  Abiertos: {len(abiertos)}  Filtrados: {len(filtrados)}',
        ''
    ]
    table = [f"{'Puerto':<8} {'Estado':<10} {'Servicio':<20} Versión", '-'*60]
    for item in resultados:
        port = f"{item['port']:<8}"
        state = 'ABIERTO' if item['state'] == 'open' else 'FILTRADO'
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
    click.echo('\n')

@cli.command(name='vuln-check')
def vuln_check_cmd():
    """Chequeo rápido de vulnerabilidades en HOST y sus subdominios; guarda resultado en /output"""
    report = vuln_check(URL_BASE)

    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'vuln_check-{HOST}.txt')
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report)

    click.echo(report)

@cli.command(name='enum-subdomains')
def cmd_enum_subdomains():
    """Enumera subdominios de HOST definido en config.py y guarda resultado en /output"""
    encontrados = enum_subdomains_tool(domain=HOST)

    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'subdomains-{HOST}.txt')
    header = [
        'ENUMERACIÓN DE SUBDOMINIOS',
        f'Target: {HOST}',
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
    click.echo('\n')

@cli.command(name='dirb')
@click.option('--max-depth', default=2, help='Profundidad máxima de crawling')
@click.option('--verbose', is_flag=True, help='Mostrar detalles en consola')
def dirb(max_depth, verbose):
    """Crawling de directorios internos y guarda resultado en /output"""
    results = crawl_links(URL_BASE, max_depth=max_depth, verbose=verbose)
    total = len(results)

    max_path_len = max((len(path) for path, _ in results), default=len('Path'))
    col_width = max(max_path_len, len('Path')) + 2

    os.makedirs('output', exist_ok=True)
    filename = os.path.join('output', f'dirb_scan-{HOST}.txt')
    header = [
        'CRAWLING DE DIRECTORIOS AVANZADO',
        f'Target: {HOST}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Total: {total}',
        ''
    ]
    rows = [f"{path:<{col_width}} {status}" for path, status in results]
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + rows))

    click.echo(Fore.CYAN + '\n' + '═'*(col_width + 8))
    click.echo(Fore.YELLOW + '🔥 CRAWLING DE DIRECTORIOS AVANZADO'.center(col_width + 8))
    click.echo(Fore.CYAN + '═'*(col_width + 8))
    click.echo(Fore.CYAN + f"{'Path':<{col_width}} Status")
    click.echo(Fore.WHITE + '-'*(col_width + len(' Status')))
    for path, status in results:
        color = Fore.GREEN if status < 400 else Fore.RED
        click.echo(color + f"{path:<{col_width}} {status}")
    click.echo('\n')

@cli.command(name='sniff-packets')
@click.option('--interface', default=None, help='Interfaz a capturar (por defecto todas)')
@click.option('--count', default=0, type=int, help='Número de paquetes (0=ilimitado)')
@click.option('--timeout', default=10, type=int, help='Tiempo de captura en segundos')
def sniff_packets_cmd(interface, count, timeout):
    """Captura paquetes de red y guarda PCAP en /output"""
    data = sniff_packets(interface=interface, count=count, timeout=timeout)
    filepath = save_pcap(data)
    click.echo(Fore.GREEN + f"Paquetes capturados en {filepath}")

@cli.command(name='whois')
@click.argument('domain')
def whois_cmd(domain):
    """Obtiene datos WHOIS para un dominio y guarda el reporte en /output"""
    try:
        info = cmd_whois.callback(domain)
    except click.ClickException as e:
        click.echo(Fore.RED + str(e))
        return

    # cmd_whois already handles saving and printing


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
        ('0', 'Salir')
    ]
    click.echo(Fore.CYAN + "Menú de herramientas disponibles:")
    for key, cmd in options:
        click.echo(Fore.YELLOW + f"  {key}. {cmd}")
    choice = click.prompt(Fore.MAGENTA + "Selecciona una opción", default='0')
    if choice == '0':
        sys.exit(0)
    for key, cmd in options:
        if choice == key and cmd != 'Salir':
            if cmd == 'geoip':
                ip = click.prompt(Fore.MAGENTA + "Ingresa la IP a geolocalizar")
                subprocess.call([sys.executable, sys.argv[0], cmd, ip])
            elif cmd == 'whois':
                domain = click.prompt(Fore.MAGENTA + "Ingresa el dominio para WHOIS")
                subprocess.call([sys.executable, sys.argv[0], cmd, domain])
            else:
                subprocess.call([sys.executable, sys.argv[0], cmd])
            return
    click.echo(Fore.RED + "Opción inválida. Saliendo.")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        show_menu()
    else:
        cli()