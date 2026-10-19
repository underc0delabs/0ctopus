# Archivo: tools/header_analyzer.py

import os
import click
import requests
from datetime import datetime
from config import URL_BASE as DEFAULT_URL

# Cabeceras de seguridad recomendadas y una breve descripción
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'Fuerza HTTPS (HSTS)',
    'Content-Security-Policy':   'Mitiga XSS e inyección de contenido',
    'X-Frame-Options':           'Protege contra clickjacking',
    'X-Content-Type-Options':    'Evita MIME-sniffing (nosniff)',
    'Referrer-Policy':           'Controla la cabecera Referer',
    'Permissions-Policy':        'Restringe APIs del navegador',
    'X-XSS-Protection':          'Filtro XSS (legacy)',
}


def analyze_headers(url: str) -> dict:
    """
    Realiza una petición y analiza las cabeceras de respuesta.

    Retorna un diccionario con las cabeceras crudas, las de seguridad
    presentes y las ausentes.
    """
    resp = requests.get(url, timeout=10, allow_redirects=True)
    headers = dict(resp.headers)

    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]

    return {
        'status': resp.status_code,
        'final_url': resp.url,
        'headers': headers,
        'present': present,
        'missing': missing,
    }


@click.command(name='header-analyzer')
@click.argument('url', required=False)
def cmd_header_analyzer(url):
    """Audita las cabeceras de seguridad HTTP de una URL."""
    url = url or DEFAULT_URL
    click.echo(f"🛡️  Analizando cabeceras de: {click.style(url, fg='cyan')}\n")

    try:
        data = analyze_headers(url)
    except Exception as e:
        raise click.ClickException(f"❌ Error al conectar: {e}")

    click.echo(click.style(f"[+] Status: {data['status']}  →  {data['final_url']}\n", fg='blue'))

    # Fingerprint básico del servidor
    server = data['headers'].get('Server')
    powered = data['headers'].get('X-Powered-By')
    if server:
        click.echo(f"  🖥️  Server      : {server}")
    if powered:
        click.echo(f"  ⚙️  X-Powered-By: {powered}")
    click.echo()

    click.echo(click.style("🔒 Cabeceras de seguridad presentes:", bold=True))
    if data['present']:
        for h, v in data['present'].items():
            click.echo(click.style(f"  ✔ {h}: {v}", fg='green'))
    else:
        click.echo(click.style("  (ninguna)", fg='red'))

    click.echo(click.style("\n⚠️  Cabeceras de seguridad ausentes:", bold=True))
    if data['missing']:
        for h in data['missing']:
            click.echo(click.style(f"  ✘ {h}  — {SECURITY_HEADERS[h]}", fg='red'))
    else:
        click.echo(click.style("  (ninguna, ¡bien!)", fg='green'))

    # Guardar reporte
    os.makedirs('output', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join('output', f'headers_{ts}.txt')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"ANALISIS DE CABECERAS\nURL: {data['final_url']}\nStatus: {data['status']}\n\n")
        f.write("== Todas las cabeceras ==\n")
        for k, v in data['headers'].items():
            f.write(f"{k}: {v}\n")
        f.write("\n== Seguridad ausentes ==\n")
        for h in data['missing']:
            f.write(f"{h}\n")

    click.echo(click.style(f"\n✅ Reporte guardado en: {filepath}", fg='green', bold=True))

    # Reporte HTML
    from tools import report
    present_rows = [['✔ ' + h, v, 'Presente'] for h, v in data['present'].items()]
    missing_rows = [['✘ ' + h, SECURITY_HEADERS[h], 'Ausente'] for h in data['missing']]
    html_path = report.save(
        tool='header-analyzer', title='Análisis de cabeceras de seguridad', target=data['final_url'],
        stats=[report.stat('Status HTTP', data['status'], 'info'),
               report.stat('Presentes', len(data['present']), 'ok'),
               report.stat('Ausentes', len(data['missing']), 'bad')],
        sections=[
            report.keyvalue('Servidor', {
                'URL final': data['final_url'],
                'Server': data['headers'].get('Server', '—'),
                'X-Powered-By': data['headers'].get('X-Powered-By', '—'),
            }),
            report.table('Cabeceras de seguridad', ['Cabecera', 'Valor / Descripción', 'Estado'],
                         present_rows + missing_rows, status_col=2),
            report.keyvalue('Todas las cabeceras', data['headers']),
        ],
    )
    click.echo(click.style(f"📄 Reporte HTML: {html_path}", fg='green', bold=True))


if __name__ == '__main__':
    cmd_header_analyzer()
