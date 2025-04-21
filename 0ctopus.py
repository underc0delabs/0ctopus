# Archivo: 0ctopus.py
#!/usr/bin/env python3
import os
import click
from colorama import init, Fore, Style
from datetime import datetime
from config import HOST, URL_BASE
from tools.portscanner import scan as portscan

# Inicializa colorama
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
    click.echo(Fore.GREEN + BANNER)

@cli.command()
def scan_ports():
    """Escaneo avanzado de puertos con detección de servicios y guarda resultado en /output"""
    resultados = portscan(common=True)
    total = len(resultados)
    abiertos = [r for r in resultados if r["state"] == "open"]
    filtrados = [r for r in resultados if r["state"] == "filtered"]

    # Preparar directorio y archivo de salida sin timestamp para reemplazar siempre
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f'port_scan-{HOST}.txt')

    # Construir contenido para archivo
    lines = []
    lines.append('ESCANEO DE PUERTOS AVANZADO')
    lines.append(f'Target: {HOST}')
    lines.append(f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}')
    lines.append(f'Total puertos: {total} (Abiertos: {len(abiertos)}, Filtrados: {len(filtrados)})')
    lines.append('')

    def table_lines(data, title):
        tbl = []
        tbl.append(title)
        tbl.append(f"{'Puerto':<8}{'Estado':<12}{'Servicio':<20}{'Versión'}")
        tbl.append('-' * 60)
        for item in data:
            port = f"{item['port']:<8}"
            state = 'ABIERTO' if item['state']=='open' else 'FILTRADO'
            service = item['service']
            version = item['version']
            tbl.append(f"{port}{state:<12}{service:<20}{version}")
        tbl.append('')
        return tbl

    lines += table_lines(abiertos, 'PUERTOS ABIERTOS')
    lines += table_lines(filtrados, 'PUERTOS FILTRADOS')

    # Escribir o sobrescribir archivo de salida
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    # Imprimir en pantalla
    click.echo(Fore.CYAN + '\n' + '═' * 60)
    click.echo(Fore.YELLOW + '🔥 ESCANEO DE PUERTOS AVANZADO'.center(60))
    click.echo(Fore.CYAN + '═' * 60)
    click.echo(Fore.GREEN + f"🔗 Target: {HOST}")
    click.echo(Fore.BLUE + f"🕒 Inicio: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    click.echo(Fore.MAGENTA + f"📊 Total puertos: {total}")
    click.echo(Fore.GREEN + f"✅ Abiertos: {len(abiertos)}" + Fore.RED + f"   🚫 Filtrados: {len(filtrados)}\n")

    def print_table(data, title, is_open):
        if not data:
            return
        click.echo((Fore.GREEN if is_open else Fore.YELLOW) + f"\n{title.center(60, '─')}" + Style.RESET_ALL)
        click.echo(Fore.CYAN + f"{'Puerto':<8}{'Estado':<12}{'Servicio':<20}{'Versión'}")
        click.echo(Fore.WHITE + '-' * 60)
        for item in data:
            port_text = f"{item['port']:<8}"
            state_text = 'ABIERTO' if item['state']=='open' else 'FILTRADO'
            state_col = f"{state_text:<12}"
            service_col = f"{item['service']:<20}"
            version_col = f"{item['version']}"
            click.echo(
                Fore.CYAN + port_text +
                (Fore.GREEN if item['state']=='open' else Fore.YELLOW) + state_col +
                Style.RESET_ALL + Fore.BLUE + service_col + Fore.WHITE + version_col
            )
        click.echo('')

    print_table(abiertos, 'PUERTOS ABIERTOS', True)
    print_table(filtrados, 'PUERTOS FILTRADOS', False)

    click.echo(Fore.CYAN + '═' * 60)
    click.echo(Fore.GREEN + f"🎯 Escaneo completado: {datetime.now().strftime('%H:%M:%S')}".center(60))
    click.echo(Fore.CYAN + '═' * 60 + '\n')

# Puedes agregar aquí otros comandos (enum_subdomains, dirb_scan, vuln_check, sniff, etc.)

if __name__ == '__main__':
    cli()
