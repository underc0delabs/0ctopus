# Archivo: tools/dns_recon.py

import os
import click
import dns.resolver
from datetime import datetime
from config import HOST as DEFAULT_DOMAIN

# Tipos de registro a consultar
RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
DNS_TIMEOUT = 5


def query_records(domain: str) -> dict:
    """
    Consulta varios tipos de registros DNS para un dominio.

    Retorna un diccionario {tipo: [valores]}.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT

    results = {}
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except dns.resolver.NoNameservers:
            results[rtype] = []
        except Exception:
            results[rtype] = []
    return results


@click.command(name='dns-recon')
@click.argument('domain', required=False)
def cmd_dns_recon(domain):
    """Consulta registros DNS (A/AAAA/MX/NS/TXT/CNAME/SOA) de un dominio."""
    domain = domain or DEFAULT_DOMAIN
    click.echo(f"🌐  Consultando registros DNS para: {click.style(domain, fg='cyan')} 🕵️\n")

    results = query_records(domain)

    lines = []
    for rtype, values in results.items():
        if values:
            click.echo(click.style(f"  {rtype:6}", fg='yellow', bold=True))
            for v in values:
                click.echo(f"    - {v}")
                lines.append(f"{rtype}\t{v}")
        else:
            click.echo(click.style(f"  {rtype:6} (sin registros)", fg='white'))

    # Guardar reporte
    os.makedirs('output', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join('output', f'dns_recon-{domain}_{ts}.txt')
    header = [
        'RECONOCIMIENTO DNS',
        f'Target: {domain}',
        f'Inicio: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}',
        ''
    ]
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + lines))

    click.echo(click.style(f"\n✅ Reporte guardado en: {filepath}", fg='green', bold=True))

    # Reporte HTML
    from tools import report
    total = sum(len(v) for v in results.values())
    rows = [[rt, v] for rt, vals in results.items() for v in vals]
    html_path = report.save(
        tool='dns-recon', title='Reconocimiento DNS', target=domain,
        stats=[report.stat('Registros', total, 'ok'),
               report.stat('Tipos con datos', sum(1 for v in results.values() if v), 'info')],
        sections=[report.table('Registros DNS', ['Tipo', 'Valor'], rows, status_col=0)
                  if rows else report.listing('Registros DNS', ['Sin registros'])],
    )
    click.echo(click.style(f"📄 Reporte HTML: {html_path}", fg='green', bold=True))


if __name__ == '__main__':
    cmd_dns_recon()
