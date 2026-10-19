import os
import click
import whois
from datetime import datetime

@click.command(name='whois')
@click.argument('domain')
def cmd_whois(domain):
    """Obtiene datos WHOIS para un dominio y guarda el reporte en /output"""
    click.echo(f"🌐  Obteniendo WHOIS para: {click.style(domain, fg='cyan')} 🕵️")
    try:
        info = whois.whois(domain)
    except Exception as e:
        raise click.ClickException(f"❌ Error al obtener WHOIS: {e}")

    # Campos destacados
    domain_name     = info.domain_name
    registrar       = info.registrar
    whois_server    = info.whois_server
    creation_date   = info.creation_date
    expiration_date = info.expiration_date
    updated_date    = info.updated_date
    name_servers    = info.name_servers
    status          = info.status
    emails          = info.emails
    dnssec          = info.dnssec

    click.echo(click.style("\n🔍 Información relevante:", bold=True))
    click.echo(f"  🏷️  Dominio     : {domain_name}")
    click.echo(f"  🏢  Registrador : {registrar}")
    click.echo(f"  🗄️  WHOIS Server: {whois_server}")
    click.echo(f"  ⏳  Creación    : {creation_date}")
    click.echo(f"  ❌  Expiración  : {expiration_date}")
    click.echo(f"  🔄  Actualizado : {updated_date}")
    click.echo(f"  🌐  NameServers : {', '.join(name_servers) if name_servers else 'N/A'}")
    click.echo(f"  ⚙️  Status      : {', '.join(status) if isinstance(status, (list, tuple)) else status}")
    click.echo(f"  📧  Emails      : {', '.join(emails) if isinstance(emails, (list, tuple)) else emails}")
    click.echo(f"  🔐  DNSSEC      : {dnssec}\n")

    # Guardar reporte completo
    os.makedirs('output', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"whois_{domain}_{timestamp}.txt"
    filepath = os.path.join('output', filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        for key, value in info.items():
            f.write(f"{key}: {value}\n")

    click.echo(click.style(f"✅ Reporte WHOIS guardado en: {filepath}", fg='green', bold=True))

    # Reporte HTML
    from tools import report
    def _fmt(v):
        return ', '.join(str(x) for x in v) if isinstance(v, (list, tuple)) else str(v)
    highlights = {
        'Dominio': _fmt(domain_name), 'Registrador': _fmt(registrar),
        'WHOIS Server': _fmt(whois_server), 'Creación': _fmt(creation_date),
        'Expiración': _fmt(expiration_date), 'Actualizado': _fmt(updated_date),
        'Name Servers': _fmt(name_servers), 'Status': _fmt(status),
        'Emails': _fmt(emails), 'DNSSEC': _fmt(dnssec),
    }
    full = {k: _fmt(v) for k, v in info.items()}
    html_path = report.save(
        tool='whois', title='Consulta WHOIS', target=domain,
        stats=[report.stat('Registrador', _fmt(registrar) or '—', 'info')],
        sections=[report.keyvalue('Información relevante', highlights),
                  report.keyvalue('Datos completos', full)],
    )
    click.echo(click.style(f"📄 Reporte HTML: {html_path}", fg='green', bold=True))

if __name__ == '__main__':
    cmd_whois()
