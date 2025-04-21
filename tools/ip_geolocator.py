import os
import click
import requests
from datetime import datetime
from typing import Dict

# API gratuita de geolocalización (ip-api.com)
API_URL = "http://ip-api.com/json/"


def geolocate_ip(ip: str) -> Dict:
    """
    Consulta la API de ip-api.com para obtener datos de geolocalización.

    Parámetros:
      ip: Dirección IP a consultar

    Retorna:
      Diccionario con los campos devueltos por la API.
    """
    resp = requests.get(f"{API_URL}{ip}", timeout=5)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "success":
        raise click.ClickException(f"Geolocalización fallida: {data.get('message', 'Unknown error')}")
    return data


def save_geo_report(data: Dict, output_dir: str = "output") -> str:
    """
    Guarda el reporte de geolocalización en un archivo JSON.

    Parámetros:
      data: Diccionario con datos de geolocalización
      output_dir: Carpeta donde guardar

    Retorna:
      Ruta del archivo generado.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"geoip_{data.get('query', 'ip')}_{ts}.json"
    path = os.path.join(output_dir, filename)
    with open(path, 'w', encoding='utf-8') as f:
        import json
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


@click.command(name='geoip')
@click.argument('ip')
def cmd_geoip(ip):
    """Geolocaliza una IP y muestra/guarda la información."""
    click.echo(f"[+] Geolocalizando IP: {ip}")
    data = geolocate_ip(ip)

    # Mostrar en consola
    for key, val in data.items():
        click.echo(f"{key:15}: {val}")

    # Guardar reporte
    filepath = save_geo_report(data)
    click.echo(click.style(f"Reporte guardado en: {filepath}", fg='green'))


if __name__ == '__main__':
    cmd_geoip()
