---
name: reporting
description: Generación de reportes HTML consolidados de 0ctopus con el estilo de Underc0de. Define el esquema JSON y el comando para producir el informe ejecutivo de una evaluación dentro de output/. Usar al cerrar un pentest para consolidar los hallazgos.
---

# Skill: Reportes (0ctopus)

El motor de reportes (`tools/report.py`) genera HTML con la marca de Underc0de. Cada herramienta ya produce su propio reporte; esta skill es para el **reporte consolidado** de la evaluación.

## Comandos

```bash
# Construir un reporte consolidado desde un JSON estructurado
python 0ctopus.py report-build <archivo.json>

# Regenerar el dashboard output/index.html desde el manifiesto
python 0ctopus.py rebuild-index
```

Salidas: `output/reports/<tool>-<target>-<ts>.html`, manifiesto `output/reports.json`, dashboard `output/index.html`.

## Esquema del JSON

```json
{
  "tool": "engagement",
  "title": "Reporte consolidado de pentest — underc0de.org",
  "target": "underc0de.org",
  "stats": [
    {"label": "Riesgo global", "value": "MEDIO", "accent": "warn"},
    {"label": "Hallazgos", "value": "4", "accent": "bad"},
    {"label": "Herramientas", "value": "6", "accent": "info"}
  ],
  "sections": [
    {"type": "text", "title": "Resumen ejecutivo",
     "body": "Texto del resumen. Admite saltos de línea."},

    {"type": "table", "title": "Hallazgos priorizados",
     "headers": ["Severidad", "Hallazgo", "Evidencia", "Recomendación"],
     "rows": [
       ["Alta", "Archivo .env expuesto", "/.env -> 200", "Restringir acceso y rotar secretos"],
       ["Media", "Falta CSP", "header-analyzer", "Definir Content-Security-Policy"]
     ],
     "status_col": 0},

    {"type": "keyvalue", "title": "Alcance",
     "items": [["Objetivo", "underc0de.org"], ["Fecha", "2026-01-01"], ["Autorización", "Interna"]]},

    {"type": "list", "title": "Reportes individuales",
     "items": ["reports/scan-ports-...html", "reports/vuln-check-...html"]}
  ],
  "raw": "Texto opcional en crudo al pie del reporte."
}
```

### Campos
- **stats[].accent**: `ok` (verde), `warn` (amarillo), `bad` (rojo), `info` (celeste), `muted` (gris).
- **section.type**: `text` (body), `table` (headers+rows, `status_col` opcional colorea por estado/severidad), `keyvalue` (items = pares [clave, valor]), `list` (items).
- `status_col` colorea la columna según palabras: alta/vulnerable/ausente→rojo, media/filtrado→amarillo, baja/ok/presente→verde.

## Flujo recomendado para el reporte consolidado

1. Leé `output/reports.json` y los HTML en `output/reports/` para extraer datos reales.
2. Priorizá hallazgos por severidad y redactá el resumen ejecutivo.
3. Escribí `output/engagement.json` con el esquema de arriba.
4. `python 0ctopus.py report-build output/engagement.json`
5. Entregá la ruta del HTML y recordá al usuario abrir `output/index.html`.

No inventes hallazgos: todo debe provenir de la salida real de las herramientas.
