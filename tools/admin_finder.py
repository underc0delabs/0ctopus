import os
import click
import requests
import random
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Lista de User-Agents para rotar (solo ASCII)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

# Rutas comunes donde suele haber un panel admin (lista extensiva)
DEFAULT_PATHS = [
    "admin/", "administrator/", "admin1/", "admin2/", "admin3/", "admin4/", "admin5/",  # índices
    "usuarios/", "usuario/", "moderator/", "webadmin/", "adminarea/", "bb-admin/", "adminLogin/", "admin_area/",  # paneles UI
    "panel-administracion/", "instadmin/", "memberadmin/", "administratorlogin/", "adm/",  # paneles regionales
    "admin/account.php", "admin/index.php", "admin/login.php", "admin/admin.php",  # estructuras comunes
    "admin_area/admin.php", "admin_area/login.php", "siteadmin/login.php", "siteadmin/index.php", "siteadmin/login.html",
    "admin/account.html", "admin/index.html", "admin/login.html", "admin/admin.html",
    "admin_area/index.php", "bb-admin/index.php", "bb-admin/login.php", "bb-admin/admin.php",
    "admin/home.php", "admin_area/login.html", "admin_area/index.html", "admin/controlpanel.php",
    "admin.php", "admincp/index.asp", "admincp/login.asp", "admincp/index.html", "adminpanel.html",
    "webadmin.html", "webadmin/index.html", "webadmin/admin.html", "webadmin/login.html",
    "admin/admin_login.html", "admin_login.html", "panel-administracion/login.html", "admin/cp.php", "cp.php",
    "administrator/index.php", "administrator/login.php", "nsw/admin/login.php", "webadmin/login.php",
    "admin/admin_login.php", "admin_login.php", "administrator/account.php", "administrator.php",
    "admin_area/admin.html", "pages/admin/admin-login.php", "admin/admin-login.php", "admin-login.php",
    "bb-admin/index.html", "bb-admin/login.html", "bb-admin/admin.html", "acceso.php", "admin/home.html",
    "login.php", "modelsearch/login.php", "moderator.php", "moderator/login.php", "moderator/admin.php",
    "account.php", "pages/admin/admin-login.html", "admin-login.html", "controlpanel.php", "admincontrol.php",
    "admin/adminLogin.html", "adminLogin.html", "admin/adminLogin.html", "home.html", "rcjakar/admin/login.php",
    "adminarea/index.html", "adminarea/admin.html", "webadmin.php", "webadmin/index.php", "webadmin/admin.php",
    "admin/controlpanel.html", "admin.html", "admin/cp.html", "cp.html", "adminpanel.php", "moderator.html",
    "administrator/index.html", "administrator/login.html", "user.html", "administrator/account.html", "administrator.html",
    "login.html", "modelsearch/login.html", "moderator/login.html", "adminarea/login.html", "panel-administracion/index.html",
    "panel-administracion/admin.html", "modelsearch/index.html", "modelsearch/admin.html", "admincontrol/login.html",
    "adm/index.html", "adm.html", "moderator/admin.html", "user.php", "account.html", "controlpanel.html", "admincontrol.html",
    "panel-administracion/login.php", "wp-login.php", "adminLogin.php", "admin/adminLogin.php", "home.php", "admin.php",
    "adminarea/index.php", "adminarea/admin.php", "adminarea/login.php", "panel-administracion/index.php","panel-administracion/admin.php",
    "modelsearch/index.php", "modelsearch/admin.php", "admincontrol/login.php", "adm/admloginuser.php", "admloginuser.php",
    "admin2.php", "admin2/login.php", "admin2/index.php", "usuarios/login.php", "adm/index.php", "adm.php", "affiliate.php",
    "adm_auth.php", "memberadmin.php", "administratorlogin.php", "account.asp", "admin/account.asp", "admin/index.asp",
    "admin/login.asp", "admin/admin.asp", "admin_area/admin.asp", "admin_area/login.asp", "admin/account.html", "admin/index.html",
    "admin/login.html", "admin/admin.html", "admin_area/admin.html", "admin_area/login.html", "admin_area/index.html",
    "admin_area/index.asp", "bb-admin/index.asp", "bb-admin/login.asp", "bb-admin/admin.asp", "bb-admin/index.html",
    "bb-admin/login.html", "bb-admin/admin.html", "admin/home.html", "admin/controlpanel.html", "admin.html", "admin/cp.html",
    "cp.html", "administrator/account.html", "administrator.html", "login.html", "user.asp", "user.html", "admincp/index.asp",
    "admincp/login.asp", "admincp/index.html", "admin/adminLogin.html", "adminLogin.html", "admin/adminLogin.html", "home.html",
    "adminarea/index.html", "adminarea/admin.html", "adminarea/login.html", "panel-administracion/index.html",
    "panel-administracion/admin.html", "modelsearch/index.html", "modelsearch/admin.html", "admincontrol/login.html",
    "adm/index.html", "adm.html", "moderator/admin.html"
]

@click.command(name='find-admin')
@click.argument('base_url')
@click.option('--wordlist', '-w', type=click.Path(exists=True),
              help='Archivo con rutas personalizadas (una por línea).')
@click.option('--threads', '-t', default=10, show_default=True,
              help='Número de hilos concurrentes.')
@click.option('--timeout', default=5, show_default=True,
              help='Timeout en segundos para cada petición.')
@click.option('--random-agent/--no-random-agent', default=True,
              help='Rotar User-Agent en cada petición.')
def cmd_find_admin(base_url, wordlist, threads, timeout, random_agent):
    """
    Busca paneles de administración reales en rutas comunes
    Solo muestra los endpoints que devuelvan código 200, contengan un formulario
    con campo "password" y parezcan paneles de administración.
    """
    click.echo(f"🔍 Buscando admin panels en {click.style(base_url, fg='cyan')}")

    if wordlist:
        with open(wordlist, 'r', encoding='utf-8') as f:
            paths = [l.strip() for l in f if l.strip()]
    else:
        paths = DEFAULT_PATHS

    os.makedirs('output', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = os.path.join('output', f'adminpanels_{ts}.txt')
    session = requests.Session()
    found = []

    def probe(path):
        url = urljoin(base_url.rstrip('/') + '/', path)
        headers = {}
        if random_agent:
            headers['User-Agent'] = random.choice(USER_AGENTS)
        try:
            resp = session.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            code = resp.status_code
            content = resp.text.lower() if code == 200 else ''
        except Exception as e:
            return (path, None, str(e), False)
        is_admin = False
        if code == 200 and '<form' in content and 'password' in content:
            is_admin = True
        return (path, code, None, is_admin)

    with ThreadPoolExecutor(max_workers=threads) as executor, open(report_path, 'w', encoding='utf-8') as rpt:
        futures = {executor.submit(probe, p): p for p in paths}
        for fut in as_completed(futures):
            path, code, err, is_admin = fut.result()
            if err:
                line = f"{path:20} ERROR: {err}"
                click.echo(f"  ❌ {line}")
                rpt.write(line + "\n")
            elif is_admin:
                line = f"{path:20} -> {code}"
                click.echo(click.style(f"  ✅ {line}", fg='green'))
                rpt.write(line + "\n")
                found.append((path, code))

    click.echo(click.style(f"\n✅ Búsqueda completada. Reporte: {report_path}", fg='green'))
    if found:
        click.echo(click.style(f"   Paneles detectados: {len(found)}", fg='yellow'))
    else:
        click.echo(click.style("   No se detectaron paneles accesibles.", fg='red'))

if __name__ == '__main__':
    cmd_find_admin()
