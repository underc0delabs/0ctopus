# Reportes HTML y dashboard

0ctopus genera reportes con el estilo **"acid lab"** de Underc0de: fondo negro con grilla y **scanlines CRT**, glow neón celeste, tipografía **Pixelify Sans** (HUD) + monospace, cabecera tipo terminal y badges de severidad con glow.

## Estructura

```
output/
├── index.html          ← Dashboard (abrir en el navegador)
├── reports.json        ← Manifiesto de todos los reportes
└── reports/
    ├── scan-ports-ejemplo.com-20260101_120000.html
    ├── vuln-check-ejemplo.com-20260101_120500.html
    └── ...
```

- **Dashboard** (`index.html`): métricas globales (total de reportes, herramientas usadas, objetivo principal, último escaneo), buscador en vivo, filtros por herramienta y listado enlazado.
- **Reporte individual**: tarjetas de métricas, tablas con estados coloreados, datos clave-valor, listas y salida en crudo tipo terminal.

## Motor (`tools/report.py`)

```python
from tools import report

report.save(
    tool='scan-ports',
    title='Escaneo de puertos',
    target='ejemplo.com',
    stats=[report.stat('Abiertos', 5, 'ok'), report.stat('Filtrados', 2, 'warn')],
    sections=[report.table('Puertos', ['Puerto','Estado','Servicio'], filas, status_col=1)],
    raw='salida opcional en crudo',
)
```

Helpers de sección: `table(title, headers, rows, status_col)`, `keyvalue(title, data)`, `listing(title, items)`, `text(title, body)`, y `stat(label, value, accent)` con `accent` ∈ `ok|warn|bad|info|muted`.

## Reporte consolidado (uso agéntico)

El agente `report-writer` escribe un JSON y lo convierte en HTML:

```bash
python 0ctopus.py report-build output/engagement.json
```

Esquema del JSON:

```json
{
  "tool": "engagement",
  "title": "Reporte consolidado — ejemplo.com",
  "target": "ejemplo.com",
  "stats": [{"label": "Riesgo global", "value": "MEDIO", "accent": "warn"}],
  "sections": [
    {"type": "text", "title": "Resumen ejecutivo", "body": "..."},
    {"type": "table", "title": "Hallazgos", "headers": ["Severidad","Hallazgo","Recomendación"],
     "rows": [["Alta", "...", "..."]], "status_col": 0}
  ]
}
```

El `status_col` colorea según palabras clave: *alta/vulnerable/ausente* → rojo, *media/filtrado* → amarillo, *baja/ok/presente* → verde.

> `output/` está en `.gitignore`: los reportes son artefactos de ejecución y no se versionan.
