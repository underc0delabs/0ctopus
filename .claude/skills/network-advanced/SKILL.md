---
name: network-advanced
description: Metodologia de pentesting/seguridad para el dominio Red avanzada: reconocimiento, comprobaciones por subtema, validacion de hallazgos y severidad CVSS. Usar para coordinar a los agentes de Red avanzada.
---

# Skill: Red avanzada (0ctopus)

Metodología de evaluación de seguridad para el dominio **Red avanzada**. Trabajar **solo sobre objetivos autorizados** (ver `CLAUDE.md`). Ejecutar la CLI desde la raíz: `python 0ctopus.py <comando>`.

## Enfoque

Este dominio agrupa a varios agentes especializados de 0ctopus. Cada uno cubre un subtema; esta skill define el marco común: cómo reconocer la superficie, qué comprobar y cómo clasificar los hallazgos.

## Agentes de este dominio

- `dhcp-attacks-tester`
- `dns-rebinding-tester`
- `dns-tunneling-tester`
- `firewall-waf-tester`
- `ftp-tftp-tester`
- `ipv6-security-tester`
- `layer2-mitm-tester`
- `network-dos-resilience`
- `ntp-security-tester`
- `proxy-socks-tester`
- `rdp-security-tester`
- `ssh-hardening-auditor`

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
