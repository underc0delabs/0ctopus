# Archivo: tools/hash_identify.py

import re
import click

# Patrones de identificación por longitud/charset.
# Cada entrada: (regex compilado, lista de posibles tipos)
HASH_PATTERNS = [
    (re.compile(r'^[a-f0-9]{32}$', re.I),        ['MD5', 'NTLM', 'MD4', 'LM']),
    (re.compile(r'^[a-f0-9]{40}$', re.I),        ['SHA-1', 'RIPEMD-160']),
    (re.compile(r'^[a-f0-9]{56}$', re.I),        ['SHA-224', 'SHA3-224']),
    (re.compile(r'^[a-f0-9]{64}$', re.I),        ['SHA-256', 'SHA3-256', 'BLAKE2s']),
    (re.compile(r'^[a-f0-9]{96}$', re.I),        ['SHA-384', 'SHA3-384']),
    (re.compile(r'^[a-f0-9]{128}$', re.I),       ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool']),
    (re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$'), ['bcrypt']),
    (re.compile(r'^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$'), ['MD5 crypt (Unix)']),
    (re.compile(r'^\$5\$'),                       ['SHA-256 crypt (Unix)']),
    (re.compile(r'^\$6\$'),                       ['SHA-512 crypt (Unix)']),
    (re.compile(r'^\$y\$'),                       ['yescrypt']),
    (re.compile(r'^\$argon2(id|i|d)\$'),         ['Argon2']),
    (re.compile(r'^[a-f0-9]{32}:[a-f0-9]{32}$', re.I), ['NTLM (user:hash)', 'MD5 con salt']),
    (re.compile(r'^{SHA}[A-Za-z0-9+/=]{28}$'),   ['SHA-1 Base64 (LDAP)']),
    (re.compile(r'^[a-f0-9]{16}$', re.I),        ['MySQL (<4.1)', 'CRC']),
    (re.compile(r'^\*[A-F0-9]{40}$', re.I),      ['MySQL 4.1+ (SHA-1)']),
    (re.compile(r'^[A-Za-z0-9./]{13}$'),         ['DES crypt (Unix)']),
]


def identify(h: str) -> list[str]:
    """Devuelve una lista de posibles tipos de hash para la cadena dada."""
    h = h.strip()
    matches = []
    for pattern, types in HASH_PATTERNS:
        if pattern.match(h):
            matches.extend(types)
    # Eliminar duplicados preservando orden
    seen = set()
    return [t for t in matches if not (t in seen or seen.add(t))]


@click.command(name='hash-identify')
@click.argument('hash_value')
def cmd_hash_identify(hash_value):
    """Identifica el tipo probable de un hash a partir de su formato."""
    click.echo(f"🔎  Analizando hash: {click.style(hash_value, fg='cyan')}")
    click.echo(f"    Longitud: {len(hash_value.strip())} caracteres\n")

    matches = identify(hash_value)

    if matches:
        click.echo(click.style("Posibles tipos:", bold=True))
        for t in matches:
            click.echo(click.style(f"  • {t}", fg='green'))
    else:
        click.echo(click.style("❌ No se reconoció el formato del hash.", fg='red'))

    click.echo(click.style(
        "\n💡 La identificación es por formato; varios algoritmos comparten longitud.",
        fg='yellow'))

    # Reporte HTML
    from tools import report
    hv = hash_value.strip()
    html_path = report.save(
        tool='hash-identify', title='Identificación de hash', target=hv[:40] + ('…' if len(hv) > 40 else ''),
        stats=[report.stat('Longitud', f'{len(hv)} chars', 'info'),
               report.stat('Coincidencias', len(matches), 'ok' if matches else 'bad')],
        sections=[
            report.keyvalue('Hash analizado', {'Valor': hv, 'Longitud': f'{len(hv)} caracteres'}),
            report.listing('Posibles tipos', matches or ['No reconocido']),
        ],
    )
    click.echo(click.style(f"📄 Reporte HTML: {html_path}", fg='green', bold=True))


if __name__ == '__main__':
    cmd_hash_identify()
