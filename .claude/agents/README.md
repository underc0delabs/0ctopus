# Catálogo de Agentes — 0ctopus

Flota de agentes de pentesting de Underc0de para Claude Code. El **orquestador** coordina; los **especialistas** ejecutan; el **redactor** consolida. Todos trabajan **solo sobre objetivos autorizados** (ver `CLAUDE.md`).

## Coordinación
- `pentest-orchestrator` — planifica la evaluación y delega en los especialistas, luego en el redactor.
- `report-writer` — consolida hallazgos en reportes HTML dentro de `output/`.

## Especialistas base (usan la CLI de 0ctopus)
- `recon-specialist` — OSINT, subdominios, DNS, WHOIS, geo, histórico.
- `web-specialist` — vulns web, cabeceras, directorios, paneles admin.
- `network-specialist` — puertos/servicios, hosts LAN, tráfico.
- `wireless-specialist` — WiFi, handshakes, cracking.

## Web / API (12)
`web-owasp-top10` · `api-rest-security` · `graphql-security` · `jwt-token-tester` · `sql-injection-specialist` · `xss-specialist` · `ssrf-specialist` · `xxe-injection-tester` · `csrf-tester` · `access-control-idor` · `file-upload-tester` · `cors-misconfig-tester`

## Autenticación / Identidad (3)
`oauth2-oidc-tester` · `saml-sso-tester` · `session-management-tester`

## Mobile (8)
`android-apk-analyzer` · `ios-ipa-analyzer` · `mobile-frida-dynamic` · `mobile-mitm-network` · `mobile-insecure-storage` · `mobile-deeplink-tester` · `react-native-analyzer` · `flutter-app-analyzer`

## Streaming / Medios (5)
`drm-security-analyzer` · `hls-dash-streaming-tester` · `rtmp-rtsp-stream-tester` · `media-cdn-tester` · `video-watermark-analyzer`

## Cloud / Contenedores (9)
`aws-security-auditor` · `azure-security-auditor` · `gcp-security-auditor` · `kubernetes-security-auditor` · `docker-container-auditor` · `terraform-iac-scanner` · `s3-storage-bucket-hunter` · `serverless-function-tester` · `cloud-iam-analyzer`

## Red / Infraestructura (6)
`network-deep-mapper` · `smb-enumerator` · `snmp-enumerator` · `vpn-security-tester` · `network-segmentation-tester` · `email-security-tester`

## Active Directory / Windows / Linux (5)
`active-directory-auditor` · `kerberos-attack-tester` · `ldap-enumerator` · `windows-privesc-auditor` · `linux-privesc-auditor`

## Wireless / RF / IoT (4)
`bluetooth-ble-tester` · `iot-firmware-analyzer` · `rfid-nfc-tester` · `sdr-rf-analyzer`

## OSINT / Social (3)
`osint-corporate-recon` · `phishing-campaign-simulator` · `metadata-document-analyzer`

## Reversing / Binario / Malware (3)
`binary-reverse-engineer` · `malware-static-analyzer` · `fuzzing-specialist`

## Cripto / DevSecOps (2)
`tls-ssl-deep-tester` · `secrets-supplychain-scanner`

---

**Total: 66 agentes** (2 coordinación + 4 base + 60 especialistas avanzados).

Skills asociadas en `.claude/skills/`: `recon`, `web-audit`, `network-scan`, `wifi-audit`, `mobile-audit`, `cloud-audit`, `streaming-audit`, `reporting`.
