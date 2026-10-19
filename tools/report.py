# Archivo: tools/report.py
# ---------------------------------------------------------------------------
# Motor de reportes HTML de 0ctopus con el estilo visual de Underc0de.
#
# Genera:
#   - output/reports/<tool>-<target>-<ts>.html   (un HTML por reporte)
#   - output/reports.json                         (manifiesto de reportes)
#   - output/index.html                           (dashboard general)
#
# Uso típico desde una herramienta:
#   from tools.report import save, table, keyvalue, listing, text, stat
#   save(
#       tool='scan-ports',
#       title='Escaneo de puertos',
#       target='underc0de.org',
#       stats=[stat('Abiertos', 5, 'ok'), stat('Filtrados', 2, 'warn')],
#       sections=[table('Puertos', ['Puerto','Estado','Servicio'], rows)],
#   )
# ---------------------------------------------------------------------------

import os
import re
import json
import html
import base64
from datetime import datetime

# --- Rutas -----------------------------------------------------------------
OUTPUT_DIR = 'output'
REPORTS_DIR = os.path.join(OUTPUT_DIR, 'reports')
MANIFEST = os.path.join(OUTPUT_DIR, 'reports.json')
INDEX = os.path.join(OUTPUT_DIR, 'index.html')

# --- Marca Underc0de -------------------------------------------------------
# Logo oficial de 0ctopus embebido (data URI) para reportes autónomos.
_LOGO_FILE = os.path.join(os.path.dirname(__file__), 'assets', '0ctopus-logo-sm.png')
_LOGO_FALLBACK = 'https://underc0de.org/assets/img/pulpo-blanco.png'
_logo_cache = None


def _logo_src():
    """Devuelve el logo como data URI (cacheado); si falta, usa la URL remota."""
    global _logo_cache
    if _logo_cache is None:
        try:
            with open(_LOGO_FILE, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('ascii')
            _logo_cache = f'data:image/png;base64,{b64}'
        except OSError:
            _logo_cache = _LOGO_FALLBACK
    return _logo_cache


LOGO_URL = _logo_src()
BRAND = 'Underc0de'

# Paleta oficial (manual de marca Underc0de "acid lab")
PALETTE = {
    'azul': '#212349',
    'celeste': '#3CB7EA',
    'azul2': '#3DA4DD',
    'azul3': '#4594D1',
    'rosa': '#ff4d6d',
    'verde': '#7dffb0',
    'amarillo': '#F6B40E',
}

# Mapa de estado -> color de acento para badges/tiles
ACCENTS = {
    'ok': PALETTE['verde'],
    'warn': PALETTE['amarillo'],
    'bad': PALETTE['rosa'],
    'info': PALETTE['celeste'],
    'muted': '#7f8bb0',
}


# ===========================================================================
# Helpers para construir secciones (API pública)
# ===========================================================================
def stat(label, value, accent='info'):
    """Una tarjeta de métrica para la fila superior del reporte."""
    return {'label': str(label), 'value': str(value), 'accent': accent}


def table(title, headers, rows, status_col=None):
    """
    Sección de tabla.
      headers:    lista de encabezados
      rows:       lista de filas (cada fila es lista de celdas)
      status_col: índice de columna que colorea la fila (opcional)
    """
    return {'type': 'table', 'title': title, 'headers': list(headers),
            'rows': [list(r) for r in rows], 'status_col': status_col}


def keyvalue(title, data):
    """Sección clave-valor. data: dict o lista de tuplas (clave, valor)."""
    items = list(data.items()) if isinstance(data, dict) else list(data)
    return {'type': 'keyvalue', 'title': title, 'items': items}


def listing(title, items):
    """Sección de lista simple."""
    return {'type': 'list', 'title': title, 'items': list(items)}


def text(title, body):
    """Sección de texto preformateado (bloque tipo terminal)."""
    return {'type': 'text', 'title': title, 'body': str(body)}


# ===========================================================================
# CSS compartido (dashboard + reportes)
# ===========================================================================
def _css():
    return """
:root{
  --azul:#212349; --celeste:#3CB7EA; --c2:#3DA4DD; --c3:#4594D1;
  --rosa:#ff4d6d; --verde:#7dffb0; --amarillo:#F6B40E;
  --negro:#000; --blanco:#fff;
  --bg:#05060d; --panel:#0a0c18; --panel2:#0e1122; --border:#1c2347;
  --text:#d7e3ff; --muted:#6f7cb0;
  --glow:0 0 18px color-mix(in srgb,var(--celeste) 45%,transparent),0 0 2px var(--celeste);
  --glow-soft:0 0 10px color-mix(in srgb,var(--celeste) 30%,transparent);
  --f-display:"Pixelify Sans",ui-monospace,Consolas,monospace;
  --f-body:"Roboto",system-ui,-apple-system,"Segoe UI",sans-serif;
  --f-mono:ui-monospace,"Cascadia Mono","DejaVu Sans Mono",Consolas,monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;font-family:var(--f-body);color:var(--text);background:var(--bg);
  background-image:
    radial-gradient(circle at 50% -10%,color-mix(in srgb,var(--celeste) 10%,transparent),transparent 55%),
    radial-gradient(circle at center,color-mix(in srgb,var(--celeste) 9%,transparent) 0 1px,transparent 1.6px);
  background-size:auto,38px 38px;background-position:center,19px 19px;
  line-height:1.55;position:relative;
}
/* Scanlines + viñeta CRT */
body::after{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:
    repeating-linear-gradient(0deg,transparent 0 2px,rgba(0,0,0,.14) 2px 3px),
    radial-gradient(ellipse at center,transparent 60%,rgba(0,0,0,.45) 100%);
  mix-blend-mode:multiply;
}
a{color:var(--celeste);text-decoration:none}
a:hover{text-decoration:underline;text-shadow:var(--glow-soft)}
.wrap{max-width:1120px;margin:0 auto;padding:0 16px 72px;position:relative;z-index:1}

/* cursor parpadeante */
.cursor{display:inline-block;width:.6ch;height:1em;background:var(--celeste);
  box-shadow:var(--glow);animation:blink 1.05s steps(2,start) infinite;vertical-align:-2px;margin-left:4px}
@keyframes blink{50%{opacity:0}}
@keyframes pulpo-float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}

/* HUD superior tipo terminal */
.hud{font-family:var(--f-mono);font-size:11px;color:var(--muted);letter-spacing:2px;
  border-bottom:1px solid var(--border);padding:6px 16px;background:#02030a;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hud b{color:var(--verde)}

/* Header */
.top{position:relative;border-bottom:1px solid var(--border);
  background:linear-gradient(180deg,color-mix(in srgb,var(--azul) 70%,transparent) 0%,transparent 130%);
  margin-bottom:26px;box-shadow:0 1px 0 color-mix(in srgb,var(--celeste) 30%,transparent)}
.top-inner{max-width:1120px;margin:0 auto;padding:22px 16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.logo{height:56px;width:auto;filter:drop-shadow(0 0 12px color-mix(in srgb,var(--celeste) 75%,transparent));
  animation:pulpo-float 5s ease-in-out infinite}
.brand{font-family:var(--f-display);font-size:30px;letter-spacing:1px;color:var(--blanco);text-shadow:var(--glow-soft)}
.brand b{color:var(--celeste);text-shadow:var(--glow)}
.brand .sub{display:block;font-family:var(--f-mono);font-size:11px;color:var(--celeste);
  letter-spacing:4px;text-transform:uppercase;margin-top:3px;text-shadow:var(--glow-soft)}
.top .spacer{flex:1}
.pill{font-family:var(--f-mono);font-size:12px;color:var(--celeste);border:1px solid var(--celeste);
  padding:6px 13px;border-radius:4px;background:#02030a;box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--celeste) 25%,transparent),var(--glow-soft)}
.pill:hover{text-decoration:none;box-shadow:var(--glow)}

h1.title{font-family:var(--f-display);font-size:34px;margin:8px 0 2px;color:var(--blanco);
  text-shadow:var(--glow);letter-spacing:1px}
h1.title::before{content:">_ ";color:var(--celeste)}
.meta{font-family:var(--f-mono);font-size:13px;color:var(--muted);display:flex;gap:8px;
  flex-direction:column;margin:12px 0 26px;border-left:2px solid var(--celeste);padding:8px 0 8px 14px;
  background:linear-gradient(90deg,color-mix(in srgb,var(--celeste) 6%,transparent),transparent)}
.meta span::before{content:"$ ";color:var(--verde)}
.meta b{color:var(--text);font-weight:500}

/* HUD stat tiles */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:0 0 30px}
.tile{background:#02030a;border:1px solid var(--border);border-radius:6px;padding:18px 18px 16px;
  position:relative;overflow:hidden;box-shadow:inset 0 0 22px rgba(0,0,0,.6)}
.tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--acc,var(--celeste));
  box-shadow:0 0 12px var(--acc,var(--celeste))}
.tile::after{content:"+";position:absolute;top:6px;right:9px;color:var(--acc,var(--celeste));
  font-family:var(--f-mono);opacity:.5}
.tile .v{font-family:var(--f-display);font-size:32px;line-height:1;color:var(--acc,var(--celeste));
  text-shadow:0 0 14px color-mix(in srgb,var(--acc,var(--celeste)) 55%,transparent)}
.tile .l{font-family:var(--f-mono);font-size:11px;text-transform:uppercase;letter-spacing:1.6px;color:var(--muted);margin-top:9px}
.tile .l::before{content:"// "}

/* Section */
.section{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin:0 0 22px;overflow:hidden;
  box-shadow:inset 0 0 0 1px rgba(60,183,234,.06)}
.section > h2{font-family:var(--f-display);font-size:19px;margin:0;padding:13px 18px;color:var(--celeste);
  border-bottom:1px solid var(--border);background:linear-gradient(90deg,var(--panel2),transparent);
  letter-spacing:1px;text-shadow:var(--glow-soft)}
.section > h2::before{content:"[ ";color:var(--verde)}
.section > h2::after{content:" ]";color:var(--verde)}
.section .body{padding:4px 2px}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 16px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-family:var(--f-mono);font-size:11px;text-transform:uppercase;letter-spacing:1.4px;color:var(--celeste);
  background:#02030a}
th::before{content:"# ";color:var(--muted)}
td{font-family:var(--f-mono);word-break:break-word;color:var(--text)}
tbody tr{transition:background .12s}
tbody tr:hover{background:color-mix(in srgb,var(--celeste) 8%,transparent);box-shadow:inset 2px 0 var(--celeste)}
.row-ok td:first-child{box-shadow:inset 3px 0 var(--verde)}
.row-bad td:first-child{box-shadow:inset 3px 0 var(--rosa)}
.row-warn td:first-child{box-shadow:inset 3px 0 var(--amarillo)}

/* key/value */
.kv{display:grid;grid-template-columns:210px 1fr;gap:1px;background:var(--border)}
.kv .k,.kv .v{background:var(--panel);padding:9px 16px;font-family:var(--f-mono);font-size:13px}
.kv .k{color:var(--celeste);text-transform:uppercase;font-size:11px;letter-spacing:1px}
.kv .k::after{content:" ::";color:var(--muted)}
.kv .v{color:var(--text)}

/* list */
ul.clean{list-style:none;margin:0;padding:8px 0}
ul.clean li{font-family:var(--f-mono);font-size:13px;padding:7px 18px;border-bottom:1px solid var(--border)}
ul.clean li::before{content:"\\25B8 ";color:var(--celeste);text-shadow:var(--glow-soft)}

/* terminal block con chrome */
.termwrap{border-top:1px solid var(--border)}
.termbar{display:flex;align-items:center;gap:7px;padding:8px 14px;background:#02030a;border-bottom:1px solid var(--border);
  font-family:var(--f-mono);font-size:11px;color:var(--muted);letter-spacing:1px}
.termbar i{width:10px;height:10px;border-radius:50%;display:inline-block}
.termbar .r{background:var(--rosa)}.termbar .y{background:var(--amarillo)}.termbar .g{background:var(--verde)}
.termbar span{margin-left:6px}
pre.term{margin:0;padding:18px;background:#010209;color:#8af5c0;font-family:var(--f-mono);
  font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;
  text-shadow:0 0 8px rgba(125,255,176,.25);
  background-image:repeating-linear-gradient(0deg,transparent 0 2px,rgba(0,0,0,.25) 2px 3px)}

/* badges */
.badge{font-family:var(--f-mono);font-size:11px;padding:3px 10px;border-radius:3px;border:1px solid var(--border);
  background:#02030a;color:var(--celeste);white-space:nowrap;box-shadow:var(--glow-soft)}
.badge.ok{color:var(--verde);border-color:color-mix(in srgb,var(--verde) 55%,transparent);box-shadow:0 0 10px color-mix(in srgb,var(--verde) 35%,transparent)}
.badge.bad{color:var(--rosa);border-color:color-mix(in srgb,var(--rosa) 55%,transparent);box-shadow:0 0 10px color-mix(in srgb,var(--rosa) 35%,transparent)}
.badge.warn{color:var(--amarillo);border-color:color-mix(in srgb,var(--amarillo) 55%,transparent);box-shadow:0 0 10px color-mix(in srgb,var(--amarillo) 35%,transparent)}

/* dashboard */
.search{width:100%;padding:13px 16px;background:#02030a;border:1px solid var(--border);border-radius:5px;
  color:var(--text);font-family:var(--f-mono);font-size:14px;margin-bottom:18px}
.search::placeholder{color:var(--muted)}
.search:focus{outline:none;border-color:var(--celeste);box-shadow:var(--glow)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
.chip{font-family:var(--f-mono);font-size:12px;padding:6px 13px;border-radius:4px;border:1px solid var(--border);
  background:#02030a;color:var(--muted);cursor:pointer;transition:all .12s}
.chip:hover{color:var(--celeste);border-color:var(--celeste)}
.chip.active{color:var(--negro);background:var(--celeste);border-color:var(--celeste);box-shadow:var(--glow);font-weight:700}
.btn{display:inline-block;font-family:var(--f-mono);font-size:12px;padding:6px 14px;border-radius:4px;
  background:var(--celeste);color:#02030a;font-weight:700;box-shadow:var(--glow-soft)}
.btn:hover{text-decoration:none;box-shadow:var(--glow)}
.empty{text-align:center;color:var(--muted);font-family:var(--f-mono);padding:40px}

footer{text-align:center;color:var(--muted);font-family:var(--f-mono);font-size:12px;margin-top:42px;
  padding-top:20px;border-top:1px solid var(--border)}
footer b{color:var(--celeste);text-shadow:var(--glow-soft)}
footer .key{display:block;color:var(--border);font-size:10px;letter-spacing:3px;margin-top:8px;word-break:break-all}

@media(max-width:640px){.kv{grid-template-columns:1fr}.brand{font-size:22px}h1.title{font-size:26px}}
@media print{
  body{background:#fff;color:#000}body::after{display:none}
  .section,.tile{break-inside:avoid;box-shadow:none}
  .brand,.brand b,h1.title,.tile .v{text-shadow:none}
  .logo{animation:none}
}
"""


def _fonts_link():
    return ('<link rel="preconnect" href="https://fonts.googleapis.com">'
            '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
            '<link href="https://fonts.googleapis.com/css2?'
            'family=Pixelify+Sans:wght@400;500;600;700&'
            'family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">')


# Clave binaria de marca Underc0de ("underc0de" en binario) para el HUD/pie
_BIN_KEY = ('01110101 01101110 01100100 01100101 01110010 '
            '01100011 00110000 01100100 01100101')


def _header(subtitle, back_link=False):
    back = '<a class="pill" href="../index.html">&larr; Dashboard</a>' if back_link else \
           '<span class="pill">root@underc0de</span>'
    prompt = 'root@underc0de:~/0ctopus#'
    return f"""<div class="hud">{_BIN_KEY} &nbsp;::&nbsp; <b>INIT</b> underc0de.sys &nbsp;::&nbsp; status <b>ONLINE</b></div>
<header class="top"><div class="top-inner">
  <img class="logo" src="{LOGO_URL}" alt="Underc0de" onerror="this.style.display='none'">
  <div class="brand">Underc<b>0</b>de<span class="sub">{html.escape(subtitle)}</span></div>
  <div class="spacer"></div>
  {back}
</div>
<div class="hud" style="border-top:1px solid var(--border);border-bottom:none">
  <span style="color:var(--verde)">{prompt}</span> ./0ctopus --run<span class="cursor"></span>
</div></header>"""


def _footer():
    year = datetime.now().year
    return (f'<footer>// EOF &mdash; generado por <b>0ctopus</b> &middot; '
            f'Underc<b>0</b>de Security Toolkit &middot; {year}<span class="cursor"></span><br>'
            f'<a href="https://underc0de.org" target="_blank" rel="noopener">underc0de.org</a>'
            f'<span class="key">{_BIN_KEY}</span></footer>')


# ===========================================================================
# Render de secciones
# ===========================================================================
def _badge_for(value):
    """Devuelve clase de badge según el contenido textual de una celda."""
    v = str(value).lower()
    if 'vulnerable' in v:
        return 'bad'
    if any(w in v for w in ('abierto', 'open', 'success', 'presente', 'ok', '200',
                            'encontrado', 'found', 'activo')):
        return 'ok'
    if any(w in v for w in ('filtrado', 'filtered', 'warn', '403', '401', 'redirect', '301', '302')):
        return 'warn'
    if any(w in v for w in ('ausente', 'cerrado', 'closed', 'error', 'fail', '500', '404', 'missing')):
        return 'bad'
    return ''


def _render_section(s):
    t = s['type']
    title = html.escape(s['title'])
    out = [f'<section class="section"><h2>{title}</h2><div class="body">']

    if t == 'table':
        out.append('<table><thead><tr>')
        for h in s['headers']:
            out.append(f'<th>{html.escape(str(h))}</th>')
        out.append('</tr></thead><tbody>')
        sc = s.get('status_col')
        for row in s['rows']:
            cls = ''
            if sc is not None and sc < len(row):
                b = _badge_for(row[sc])
                cls = {'ok': 'row-ok', 'bad': 'row-bad', 'warn': 'row-warn'}.get(b, '')
            out.append(f'<tr class="{cls}">' if cls else '<tr>')
            for i, cell in enumerate(row):
                val = html.escape(str(cell))
                if sc is not None and i == sc:
                    b = _badge_for(cell)
                    val = f'<span class="badge {b}">{val}</span>'
                out.append(f'<td>{val}</td>')
            out.append('</tr>')
        out.append('</tbody></table>')

    elif t == 'keyvalue':
        out.append('<div class="kv">')
        for k, v in s['items']:
            out.append(f'<div class="k">{html.escape(str(k))}</div>'
                       f'<div class="v">{html.escape(str(v))}</div>')
        out.append('</div>')

    elif t == 'list':
        out.append('<ul class="clean">')
        for it in s['items']:
            out.append(f'<li>{html.escape(str(it))}</li>')
        out.append('</ul>')
        if not s['items']:
            out.append('<div class="empty">Sin resultados</div>')

    elif t == 'text':
        out.append('<div class="termwrap"><div class="termbar">'
                   '<i class="r"></i><i class="y"></i><i class="g"></i>'
                   '<span>output.log</span></div>'
                   f'<pre class="term">{html.escape(s["body"])}</pre></div>')

    out.append('</div></section>')
    return ''.join(out)


# ===========================================================================
# Render del documento de reporte
# ===========================================================================
def _render_report(tool, title, target, stats, sections, dt):
    tiles = ''.join(
        f'<div class="tile" style="--acc:{ACCENTS.get(s["accent"], ACCENTS["info"])}">'
        f'<div class="v">{html.escape(s["value"])}</div>'
        f'<div class="l">{html.escape(s["label"])}</div></div>'
        for s in stats
    )
    body = ''.join(_render_section(s) for s in sections)
    return f"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · {html.escape(target)} · 0ctopus</title>
{_fonts_link()}
<style>{_css()}</style>
</head><body>
{_header('Reporte de seguridad', back_link=True)}
<div class="wrap">
  <h1 class="title">{html.escape(title)}</h1>
  <div class="meta">
    <span>🎯 Objetivo: <b>{html.escape(target)}</b></span>
    <span>🧰 Herramienta: <b>{html.escape(tool)}</b></span>
    <span>🕒 Fecha: <b>{html.escape(dt)}</b></span>
  </div>
  <div class="stats">{tiles}</div>
  {body}
  {_footer()}
</div>
</body></html>"""


# ===========================================================================
# Dashboard / index
# ===========================================================================
def _render_dashboard(entries):
    total = len(entries)
    tools = sorted({e['tool'] for e in entries})
    last = entries[0]['datetime'] if entries else '—'
    # objetivo mas frecuente
    targets = {}
    for e in entries:
        targets[e['target']] = targets.get(e['target'], 0) + 1
    main_target = max(targets, key=targets.get) if targets else '—'

    kpis = [
        ('Reportes totales', total, 'info'),
        ('Herramientas usadas', len(tools), 'ok'),
        ('Objetivo principal', main_target, 'warn'),
        ('Último escaneo', last, 'muted'),
    ]
    tiles = ''.join(
        f'<div class="tile" style="--acc:{ACCENTS[a]}"><div class="v">{html.escape(str(v))}</div>'
        f'<div class="l">{html.escape(l)}</div></div>'
        for l, v, a in kpis
    )

    chips = '<span class="chip active" data-tool="*">Todos</span>' + ''.join(
        f'<span class="chip" data-tool="{html.escape(t)}">{html.escape(t)}</span>' for t in tools
    )

    rows = []
    for e in entries:
        statbits = ' · '.join(f'{html.escape(s["label"])}: {html.escape(s["value"])}'
                              for s in e.get('stats', [])[:3])
        rel = e['file'].replace('\\', '/')
        rel = rel[len(OUTPUT_DIR) + 1:] if rel.startswith(OUTPUT_DIR + '/') else rel
        rows.append(
            f'<tr data-tool="{html.escape(e["tool"])}" '
            f'data-search="{html.escape((e["tool"]+" "+e["target"]+" "+e["title"]).lower())}">'
            f'<td>{html.escape(e["datetime"])}</td>'
            f'<td><span class="badge">{html.escape(e["tool"])}</span></td>'
            f'<td>{html.escape(e["target"])}</td>'
            f'<td style="color:var(--muted)">{statbits}</td>'
            f'<td><a class="btn" href="{html.escape(rel)}">Ver →</a></td>'
            f'</tr>'
        )
    tbody = ''.join(rows) if rows else \
        '<tr><td colspan="5"><div class="empty">Aún no hay reportes. Ejecutá una herramienta de 0ctopus.</div></td></tr>'

    return f"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>0ctopus · Panel de Reportes · Underc0de</title>
{_fonts_link()}
<style>{_css()}</style>
</head><body>
{_header('Panel de reportes', back_link=False)}
<div class="wrap">
  <h1 class="title">Panel de Reportes</h1>
  <div class="meta"><span>Dashboard central de 0ctopus — resultados de todas las herramientas.</span></div>
  <div class="stats">{tiles}</div>

  <input id="q" class="search" type="search" placeholder="🔎 Buscar por objetivo, herramienta o título...">
  <div class="toolbar" id="chips">{chips}</div>

  <section class="section"><h2>Reportes generados ({total})</h2><div class="body">
    <table id="tbl"><thead><tr>
      <th>Fecha</th><th>Herramienta</th><th>Objetivo</th><th>Resumen</th><th></th>
    </tr></thead><tbody>{tbody}</tbody></table>
  </div></section>
  {_footer()}
</div>
<script>
const q=document.getElementById('q'),rows=[...document.querySelectorAll('#tbl tbody tr')];
let tool='*';
function apply(){{
  const term=(q.value||'').toLowerCase();
  rows.forEach(r=>{{
    const okT=tool==='*'||r.dataset.tool===tool;
    const okS=!term||(r.dataset.search||'').includes(term);
    r.style.display=(okT&&okS)?'':'none';
  }});
}}
q&&q.addEventListener('input',apply);
document.getElementById('chips').addEventListener('click',e=>{{
  const c=e.target.closest('.chip');if(!c)return;
  document.querySelectorAll('.chip').forEach(x=>x.classList.remove('active'));
  c.classList.add('active');tool=c.dataset.tool;apply();
}});
</script>
</body></html>"""


# ===========================================================================
# API principal
# ===========================================================================
def _slug(s):
    s = re.sub(r'^https?://', '', str(s))
    s = re.sub(r'[^a-zA-Z0-9._-]+', '_', s).strip('_')
    return s[:60] or 'target'


def _load_manifest():
    try:
        with open(MANIFEST, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return []


def save(tool, title, target, sections, stats=None, raw=None):
    """
    Guarda un reporte HTML, actualiza el manifiesto y regenera el dashboard.

    Parámetros:
      tool:     nombre del comando (ej. 'scan-ports')
      title:    título legible del reporte
      target:   objetivo (dominio/IP/URL)
      sections: lista de secciones (usar table()/keyvalue()/listing()/text())
      stats:    lista de métricas (usar stat()); opcional
      raw:      texto plano a adjuntar como bloque terminal; opcional

    Retorna la ruta del HTML generado.
    """
    stats = stats or []
    sections = list(sections)
    if raw:
        sections.append(text('Salida en crudo', raw))

    os.makedirs(REPORTS_DIR, exist_ok=True)
    now = datetime.now()
    ts = now.strftime('%Y%m%d_%H%M%S')
    dt_human = now.strftime('%d/%m/%Y %H:%M:%S')

    filename = f'{tool}-{_slug(target)}-{ts}.html'
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(_render_report(tool, title, target, stats, sections, dt_human))

    # Actualizar manifiesto (mas reciente primero)
    entries = _load_manifest()
    entries.insert(0, {
        'id': ts,
        'tool': tool,
        'title': title,
        'target': target,
        'datetime': dt_human,
        'timestamp': now.isoformat(timespec='seconds'),
        'file': os.path.join(REPORTS_DIR, filename),
        'stats': stats,
    })
    with open(MANIFEST, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)

    # Regenerar dashboard
    with open(INDEX, 'w', encoding='utf-8') as f:
        f.write(_render_dashboard(entries))

    return filepath


def rebuild_index():
    """Regenera el dashboard desde el manifiesto (útil tras borrar reportes)."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    entries = _load_manifest()
    with open(INDEX, 'w', encoding='utf-8') as f:
        f.write(_render_dashboard(entries))
    return INDEX


def build_from_json(path):
    """
    Construye un reporte a partir de un archivo JSON. Pensado para que un
    agente (p. ej. el 'report-writer') escriba un documento estructurado y
    lo convierta en HTML sin pasar contenido por la línea de comandos.

    Esquema esperado:
      {
        "tool": "engagement",
        "title": "Reporte consolidado ...",
        "target": "underc0de.org",
        "stats": [{"label": "...", "value": "...", "accent": "ok|warn|bad|info|muted"}],
        "sections": [
          {"type": "table", "title": "...", "headers": [...], "rows": [[...]], "status_col": 1},
          {"type": "keyvalue", "title": "...", "items": [["clave", "valor"], ...]},
          {"type": "list", "title": "...", "items": [...]},
          {"type": "text", "title": "...", "body": "..."}
        ]
      }
    """
    with open(path, 'r', encoding='utf-8') as f:
        doc = json.load(f)

    return save(
        tool=doc.get('tool', 'report'),
        title=doc.get('title', 'Reporte'),
        target=doc.get('target', '—'),
        sections=doc.get('sections', []),
        stats=doc.get('stats', []),
        raw=doc.get('raw'),
    )
