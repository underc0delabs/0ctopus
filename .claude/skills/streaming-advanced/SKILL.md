---
name: streaming-advanced
description: Metodologia de pentesting/seguridad para el dominio Streaming y medios avanzado: reconocimiento, comprobaciones por subtema, validacion de hallazgos y severidad CVSS. Usar para coordinar a los agentes de Streaming y medios avanzado.
---

# Skill: Streaming y medios avanzado (0ctopus)

Metodología de evaluación de seguridad para el dominio **Streaming y medios avanzado**. Trabajar **solo sobre objetivos autorizados** (ver `CLAUDE.md`). Ejecutar la CLI desde la raíz: `python 0ctopus.py <comando>`.

## Enfoque

Este dominio agrupa a varios agentes especializados de 0ctopus. Cada uno cubre un subtema; esta skill define el marco común: cómo reconocer la superficie, qué comprobar y cómo clasificar los hallazgos.

## Agentes de este dominio

- `audio-streaming-tester`
- `chromecast-dlna-tester`
- `hdcp-hdmi-tester`
- `iptv-middleware-tester`
- `smart-tv-app-tester`
- `widevine-cdm-analyzer`

## Metodología general

1. **Alcance y autorización**: definir objetivos, permisos y profundidad.
2. **Reconocimiento**: inventariar la superficie específica del dominio.
3. **Evaluación**: aplicar las comprobaciones de cada subtema, de menos a más intrusivo.
4. **Validación**: confirmar cada hallazgo con evidencia reproducible (sin falsos positivos).
5. **Documentación**: evidencia, impacto, severidad (CVSS) y recomendación.

## Integración con 0ctopus

- Usar los comandos de la CLI donde apliquen; cada uno deja su HTML en `output/reports/`.
- Consolidar los hallazgos con el agente `report-writer` y la skill `reporting`.

## Severidad

Clasificar por impacto y explotabilidad: **Crítica** (compromiso directo/datos sensibles), **Alta**, **Media**, **Baja**, **Informativa**. No reportar sin evidencia real.
