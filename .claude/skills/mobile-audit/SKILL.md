---
name: mobile-audit
description: Auditoría de seguridad de apps móviles (Android/iOS) siguiendo OWASP MASVS/MASTG — análisis estático y dinámico, almacenamiento, red, criptografía, resiliencia y deep links. Usar para evaluar APK/IPA, React Native y Flutter.
---

# Skill: Auditoría Móvil (0ctopus)

Guía de evaluación de apps móviles basada en **OWASP MASVS/MASTG**. Trabajar solo sobre apps y dispositivos autorizados.

## Dominios MASVS

- **STORAGE**: datos sensibles en SharedPreferences/NSUserDefaults, SQLite, Keychain/Keystore, logs, backups.
- **CRYPTO**: uso correcto de cifrado, claves embebidas, aleatoriedad.
- **AUTH**: autenticación local, biometría, sesiones.
- **NETWORK**: TLS, certificate/SSL pinning, ATS/Network Security Config.
- **PLATFORM**: componentes exportados, IPC, deep links, WebViews.
- **CODE**: ofuscación, debuggable, dependencias.
- **RESILIENCE**: root/jailbreak detection, anti-tamper, anti-hooking.

## Flujo

1. **Estático**: descompilar (apktool/jadx para Android, class-dump/Ghidra para iOS) o pasar por **MobSF**. Revisar manifiesto/Info.plist, permisos, secretos, configuración de red.
2. **Dinámico** (dispositivo autorizado): **Frida/Objection** para hooking, bypass de pinning/root (autorizado), inspección de almacenamiento y cripto en runtime.
3. **Red**: interceptar con **mitmproxy/Burp**; evaluar pinning y las APIs backend (combinar con skill `web-audit`).
4. **Frameworks**: React Native → analizar el bundle JS; Flutter → reFlutter/blutter sobre libapp.so.

## Herramientas

MobSF · apktool · jadx · Frida · Objection · mitmproxy · Burp Suite · class-dump · Ghidra · reFlutter · exiftool · semgrep.

## Severidad (ejemplos)

- Secretos/claves hardcodeados que dan acceso a backend → **Alta/Crítica**.
- Cleartext traffic / sin pinning con datos sensibles → **Alta/Media**.
- Almacenamiento inseguro de credenciales/tokens → **Alta**.
- Componentes exportados sin protección → **Media**.
- Falta de root/jailbreak detection → **Baja** (defensa en profundidad).

Documentá evidencia reproducible y pasá los hallazgos al `report-writer` (skill `reporting`).
