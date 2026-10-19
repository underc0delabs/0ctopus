# Archivo: tools/wayback_urls.py

import os
import click
import requests
from datetime import datetime
from config import HOST as DEFAULT_DOMAIN

# API CDX del Internet Archive
CDX_URL = "http://web.archive.org/cdx/search/cdx"


def fetch_wayback_urls(domain: str, limit: int = 0) -> list[str]:
    """
    Obtiene URLs históricas de un dominio desde el Wayback Machine (CDX API).

    Parámetros:
      domain: dominio objetivo (se incluyen subdominios)
      limit:  máximo de resultados (0 = sin límite)

    Retorna una lista de URLs únicas.
    """
    params = {
        'url': f'*.{domain}/*',
        'output': 'text',
        'fl': 'original',
        'collapse': 'urlkey',
    }
    if limit:
        params['limit'] = str(limit)

    resp = requests.get(CDX_URL, params=params, timeout=30)
    resp.raise_for_status()

    urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
    # Únicas preservando orden
    seen = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


@click.command(name='wayback-urls')
@click.argument('domain', required=False)
@click.option('--limit', default=0, type=int, help='Máximo de URLs (0 = sin límite)')
def cmd_wayback(domain, limit):
    """Recupera URLs históricas de un dominio desde el Wayback Machine."""
    domain = domain or DEFAULT_DOMAIN
    click.echo(f"🕰️  Consultando Wayback Machine para: {click.style(domain, fg='cyan')}\n")

    try:
        urls = fetch_wayback_urls(domain, limit=limit)
    except Exception as e:
        raise click.ClickException(f"❌ Error al consultar el archivo: {e}")

    if not urls:
        click.echo(click.style("No se encontraron URLs archivadas.", fg='yellow'))
        return

    for u in urls[:50]:
        click.echo(click.style(f"  - {u}", fg='green'))
    if len(urls) > 50:
        click.echo(click.style(f"  ... y {len(urls) - 50} más (ver reporte)", fg='white'))

    # Guardar reporte
    os.makedirs('output', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join('output', f'wayback-{domain}_{ts}.txt')
    header = [
        'URLS HISTORICAS (Wayback Machine)',
        f'Target: {domain}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        f'Total: {len(urls)}',
        ''
    ]
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + urls))

    click.echo(click.style(f"\n✅ {len(urls)} URLs guardadas en: {filepath}", fg='green', bold=True))

    # Reporte HTML
    from tools import report
    html_path = report.save(
        tool='wayback-urls', title='URLs históricas (Wayback Machine)', target=domain,
        stats=[report.stat('URLs', len(urls), 'ok')],
        sections=[report.listing('URLs archivadas', urls)],
    )
    click.echo(click.style(f"📄 Reporte HTML: {html_path}", fg='green', bold=True))


if __name__ == '__main__':
    cmd_wayback()
