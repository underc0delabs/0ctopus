# Archivo: tools/handshake_crack.py

import os
import subprocess
import click
from colorama import Fore, Style

# Directorios
WORDLIST_DIR    = os.path.join(os.path.dirname(__file__), 'wordlist')
HANDSHAKE_DIR   = os.path.join(os.path.dirname(__file__), 'wpa-handshakes')
OUTPUT_DIR      = os.path.join(os.getcwd(), 'output')

def check_hashcat():
    """Verifica si hashcat está disponible en PATH"""
    try:
        subprocess.run(['hashcat','--version'], capture_output=True, check=True)
        return True
    except Exception:
        return False

def list_files(dirpath, exts):
    """Lista archivos en dirpath que terminen con alguna de las extensiones exts"""
    if not os.path.isdir(dirpath):
        return []
    return [f for f in os.listdir(dirpath) if f.lower().endswith(exts)]

def convert_to_hc22000(handshake_path):
    """Convierte .cap/.pcap a formato .hc22000 usando hcxpcapngtool"""
    base, _ = os.path.splitext(handshake_path)
    hcfile  = base + '.hc22000'
    subprocess.run([
        'hcxpcapngtool', '-o', hcfile, handshake_path
    ], check=True)
    return hcfile

def run_hashcat(hcfile, mode, extra_args, output_file):
    """
    Ejecuta hashcat:
     - mode 0 = dict, 3 = mask
     - extra_args = lista de argumentos adicionales (p.ej. ['rockyou.txt'])
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    outfile = os.path.join(OUTPUT_DIR, output_file)
    cmd = [
        'hashcat',
        '-m', '22000',
        '-a', str(mode),
        hcfile,
        *extra_args,
        '--status',
        '--status-timer=5',
        '--outfile', outfile,
        '--outfile-format=2',   # solo mostrar contraseña
        '--quiet'
    ]
    subprocess.run(cmd, check=True)
    # luego buscamos la contraseña extraída:
    if os.path.isfile(outfile):
        with open(outfile, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines[0] if lines else None
    return None

@click.command(name='wifi-crack')
@click.option('--output', default='wifi_crack.txt', help='Nombre de archivo de salida (en carpeta output/)')
def cmd_wifi_crack(output):
    """Descifra handshakes WPA/WPA2 usando hashcat por GPU"""
    if not check_hashcat():
        click.echo(Fore.RED + "Error: no encontré el ejecutable `hashcat`. Instalalo con:")
        click.echo(Fore.CYAN + "  sudo apt install hashcat   (o descarga desde https://hashcat.net)")
        return

    # 1) Seleccionar handshake
    hs = list_files(HANDSHAKE_DIR, ('.cap','.pcap','.hc22000'))
    if not hs:
        click.echo(Fore.RED + f"No hay handshakes en {HANDSHAKE_DIR}")
        return
    click.echo(Fore.CYAN + "\nHandshakes disponibles:")
    for i,fname in enumerate(hs,1):
        click.echo(f"  {i}) {fname}")
    idx = click.prompt("Seleccioná el número del handshake", type=int)
    try:
        hs_path = os.path.join(HANDSHAKE_DIR, hs[idx-1])
    except IndexError:
        click.echo(Fore.RED + "Selección inválida.")
        return

    # 2) Convertir si es necesario
    if hs_path.lower().endswith(('.cap','.pcap')):
        click.echo(Fore.YELLOW + "Convirtiendo a formato hc22000…")
        hs_path = convert_to_hc22000(hs_path)

    # 3) Elegir método
    metodo = click.prompt(
        Fore.CYAN + "\nElige método",
        type=click.Choice(['diccionario','fuerza_bruta'], case_sensitive=False)
    )

    password = None
    if metodo == 'diccionario':
        # listar wordlists
        wls = list_files(WORDLIST_DIR, ('.txt',))
        if not wls:
            click.echo(Fore.RED + f"No hay diccionarios en {WORDLIST_DIR}")
            return
        click.echo(Fore.CYAN + "\nWordlists disponibles:")
        for i,fname in enumerate(wls,1):
            click.echo(f"  {i}) {fname}")
        idx2 = click.prompt("Seleccioná el número del diccionario", type=int)
        try:
            wl_path = os.path.join(WORDLIST_DIR, wls[idx2-1])
        except IndexError:
            click.echo(Fore.RED + "Selección inválida.")
            return
        click.echo(Fore.YELLOW + f"Iniciando ataque por diccionario con {wls[idx2-1]}…")
        password = run_hashcat(hs_path, mode=0, extra_args=[wl_path], output_file=output)

    else:
        # fuerza bruta
        click.echo(Fore.CYAN + "\nOpciones de charset:")
        click.echo("  1) minúsculas")
        click.echo("  2) MAYÚSCULAS")
        click.echo("  3) dígitos")
        click.echo("  4) símbolos")
        click.echo("  5) todos")
        opt = click.prompt("Elegí una opción (1-5)", type=int)
        cmap = {1:'?l',2:'?u',3:'?d',4:'?s',5:'?a'}
        if opt not in cmap:
            click.echo(Fore.RED + "Opción inválida.")
            return
        length = click.prompt("Longitud de la contraseña", type=int, default=6)
        mask = cmap[opt] * length
        click.echo(Fore.YELLOW + f"Iniciando fuerza bruta (mask={mask})…")
        password = run_hashcat(hs_path, mode=3, extra_args=[mask], output_file=output)

    # 4) Mostrar resultado
    if password:
        click.echo(Fore.GREEN + f"\n¡Contraseña encontrada!: {password}")
        click.echo(Fore.CYAN + f"Resultado guardado en output/{output}")
    else:
        click.echo(Fore.RED + "\nNo se encontró la contraseña.")

if __name__ == '__main__':
    cmd_wifi_crack()
