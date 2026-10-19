---
name: ad-windows-advanced
description: Metodologia de pentesting/seguridad para el dominio Active Directory y Windows: reconocimiento, comprobaciones por subtema, validacion de hallazgos y severidad CVSS. Usar para coordinar a los agentes de Active Directory y Windows.
---

# Skill: Active Directory y Windows (0ctopus)

Metodología de evaluación de seguridad para el dominio **Active Directory y Windows**. Trabajar **solo sobre objetivos autorizados** (ver `CLAUDE.md`). Ejecutar la CLI desde la raíz: `python 0ctopus.py <comando>`.

## Enfoque

Este dominio agrupa a varios agentes especializados de 0ctopus. Cada uno cubre un subtema; esta skill define el marco común: cómo reconocer la superficie, qué comprobar y cómo clasificar los hallazgos.

## Agentes de este dominio

- `adcs-tester`
- `applocker-wdac-bypass`
- `credential-dumping-detection`
- `dpapi-tester`
- `gpo-abuse-auditor`
- `ntlm-relay-tester`
- `uac-privilege-audit`
- `windows-persistence-audit`
- `wmi-dcom-tester`

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
