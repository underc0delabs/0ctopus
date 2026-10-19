---
name: streaming-audit
description: Auditoría de seguridad de plataformas de streaming y medios — DRM (Widevine/PlayReady/FairPlay), HLS/DASH, RTMP/RTSP/SRT, CDN de medios, tokens de acceso y watermarking. Usar para evaluar servicios de video/audio autorizados.
---

# Skill: Auditoría de Streaming y Medios (0ctopus)

Guía para evaluar la seguridad de plataformas de streaming. **Solo contenido/servicios propios o autorizados**; respetar derechos de autor y términos de servicio.

## Superficies

- **DRM**: Widevine (L1/L3), PlayReady (SL150/2000/3000), FairPlay. Flujo de licencias, protección de claves de contenido, validación/revocación de dispositivo.
- **Protocolos de entrega**:
  - **HLS** (M3U8) y **DASH** (MPD): manifiestos, cifrado de segmentos (AES-128/SAMPLE-AES), tokens firmados, expiración de URLs.
  - **En vivo**: RTMP/RTMPS, RTSP, SRT — autenticación de publicación/reproducción, cifrado, exposición de ingest.
- **CDN**: signed URLs/cookies, cache poisoning/deception, exposición del origen, control por geo/sesión.
- **Watermarking**: marcas forenses, identificadores de sesión/usuario, trazabilidad de filtraciones.
- **APIs**: endpoints de catálogo, licencias y cuenta (combinar con skill `web-audit`/`api-rest-security`).

## Flujo

1. Mapear el pipeline: player → manifiesto → segmentos → servidor de licencias/DRM → CDN.
2. Analizar manifiestos (M3U8/MPD) y el esquema de cifrado/tokens.
3. Evaluar la adquisición de licencias (interceptar con mitmproxy/Burp, autorizado).
4. Probar control de acceso: expiración de tokens, hotlinking, bypass por geo/sesión.
5. Revisar CDN (signed URLs, exposición de origen) y watermarking.

## Herramientas

ffmpeg · yt-dlp (autorizado) · mitmproxy / Burp Suite · mediainfo · exiftool · curl · 0ctopus: `header-analyzer`, `scan-ports`.

## Severidad (ejemplos)

- Claves de contenido o licencias accesibles sin control → **Crítica**.
- URLs de contenido sin firmar/expiración (hotlinking libre) → **Alta**.
- Origen detrás del CDN directamente accesible → **Alta/Media**.
- Segmentos sin cifrar en servicio premium → **Media**.
- Ausencia de watermarking en contenido sensible → **Baja/Informativa**.

Documentá con evidencia y pasá los hallazgos al `report-writer` (skill `reporting`).
