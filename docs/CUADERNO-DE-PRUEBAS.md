# 🧪 Cuaderno de pruebas — CyberHound Pro

Plan de pruebas de aceptación (manual/E2E) que **complementa** la suite automática
(`pytest`, 542 tests). Pensado como checklist de release: ejecutar antes de publicar
una versión.

- **Última ejecución:** 2026-06-11 · build `master`
- **Entorno:** Ubuntu 24.04, Python 3.12, venv del proyecto, SQLite, auth `none` (localhost)
- **Resultado global:** ✅ Apto (1 defecto encontrado y corregido — ver TC-WS-02)

## Cómo levantar el entorno de pruebas
```bash
python -m cyberhound web --port 18443 --host 127.0.0.1 --no-auth
# UI: https://127.0.0.1:18443  (cert autofirmado; el navegador avisará)
```
Leyenda de estado: ✅ pasa · ⚠️ pasa con observación · ❌ falla

---

## 1. Arranque e infraestructura

| ID | Caso | Pasos | Resultado esperado | Estado |
|----|------|-------|--------------------|--------|
| TC-BOOT-01 | Arranque limpio | `cyberhound web --no-auth` | Server escucha; BD SQLite inicializada; scheduler y monitor activos | ✅ |
| TC-BOOT-02 | TLS automático | Arrancar con permisos correctos en `~/.cyberhound` | Genera cert y sirve **HTTPS** (TLS 1.2+) | ✅ |
| TC-BOOT-03 | Degradación de TLS | Dir TLS no escribible | Avisa y cae a HTTP con WARNING claro (no crashea) | ✅ |
| TC-BOOT-04 | Sin permisos de log | `/var/log/cyberhound` no escribible | WARNING y log solo a consola; el server sigue | ✅ |

## 2. Autenticación y acceso

| ID | Caso | Pasos | Resultado esperado | Estado |
|----|------|-------|--------------------|--------|
| TC-AUTH-01 | Modo `none` solo localhost | Petición desde 127.0.0.1 | Acceso permitido sin login | ✅ |
| TC-AUTH-02 | Modo `none` deniega remoto | Petición desde IP no-local | `403 Solo acceso desde localhost` | ✅ (por diseño) |
| TC-AUTH-03 | Modo `jwt` exige login | Acceso sin sesión | Redirige a `/login` | ✅ |
| TC-AUTH-04 | Sesión expirada | Token caducado en una llamada API | Redirección a `/login?error=Sesión+expirada` | ✅ |

## 3. Frontend (SPA)

| ID | Caso | Pasos | Resultado esperado | Estado |
|----|------|-------|--------------------|--------|
| TC-UI-01 | Carga del SPA | GET `/` | `<title>CyberHound Pro</title>`, HTTP 200 | ✅ |
| TC-UI-02 | Assets estáticos | GET `/static/app.js`, `/static/style.css` | HTTP 200 | ✅ |
| TC-UI-03 | Render del dashboard | Abrir la UI en navegador | Tema oscuro, tarjetas (score, problemas, acciones, estado), sin errores de consola | ✅ |
| TC-UI-04 | Pestaña Nuclei presente | Inspeccionar la barra de navegación | Aparece la pestaña **☢️ Nuclei** y su panel (`data-panel="nuclei"`) | ✅ |
| TC-UI-05 | Estados vacíos | Dashboard sin escaneos previos | Muestra estados vacíos coherentes | ⚠️ Las tarjetas score/dispositivos quedan en «Cargando…» sin datos — mejorar a «Sin análisis» (cosmético) |

## 4. Scanners (E2E vía WebSocket)

Validados contra objetivos **reales en modo solo-lectura** (homelab del autor).

| ID | Scanner (tarea) | Objetivo de prueba | Resultado esperado | Obtenido | Estado |
|----|-----------------|--------------------|--------------------|----------|--------|
| TC-SCAN-01 | `audit` (hardening) | localhost | Hallazgos + score | 60 hallazgos, score 2 (incl. CVE-2024-6387) | ✅ |
| TC-SCAN-02 | `web_headers` | URLs HTTP | Detecta cabeceras de seguridad ausentes | 9 hallazgos (HSTS/X-CTO ausentes) | ✅ |
| TC-SCAN-03 | `web_exposure` | URL HTTP | Detecta recursos sensibles expuestos | 1 hallazgo (web.config) | ✅ |
| TC-SCAN-04 | `api_security` | URL HTTP | CORS/headers de API | 0 (objetivo limpio) | ✅ |
| TC-SCAN-05 | `tls` | host:443 | Evalúa certificado/protocolos | 0 (objetivo limpio) | ✅ |
| TC-SCAN-06 | `dns` | dominio | SPF/DMARC/DNSSEC/CAA | 4 hallazgos (sin SPF/DMARC/DNSSEC) | ✅ |
| TC-SCAN-07 | `subdomain_enum` | dominio | Subdominios vía CT logs | 2 (subdominio activo + resumen) | ✅ |
| TC-SCAN-08 | `nuclei` | URL | Ejecuta motor o degrada | 0 + degradación elegante (binario ausente) | ✅ |
| TC-SCAN-09 | `network` | CIDR LAN | Descubrimiento nmap | (requiere nmap + privilegios) | ⏭️ no ejecutado en este entorno |
| TC-SCAN-10 | `docker` / `code` / `malware` / `ssh` / `services` | local/remoto | Hallazgos por módulo | cubierto por suite automática | ✅ (unit) |

## 5. WebSocket / API y validación de entrada

| ID | Caso | Pasos | Resultado esperado | Estado |
|----|------|-------|--------------------|--------|
| TC-WS-01 | Dispatch de tarea válida | Enviar `{"task":"audit"}` | Emite `finding`* y `done{score}` | ✅ |
| TC-WS-02 | **Tareas web habilitadas** (regresión) | Enviar `web_exposure`/`nuclei`/… con `urls` | Ejecuta el scanner (NO «Tarea no permitida») | ✅ **Defecto encontrado y corregido**: faltaban en `ALLOWED_TASKS` y se descartaban sus parámetros. Fix + 20 tests de regresión |
| TC-WS-03 | Tarea desconocida | Enviar `{"task":"xxx"}` | Error «Tarea no permitida» y cierre limpio | ✅ |
| TC-WS-04 | Endpoints API | GET `/api/dashboard`, `/api/history`, `/api/score/trend` | HTTP 200 | ✅ |

## 6. Seguridad / robustez

| ID | Caso | Pasos | Resultado esperado | Estado |
|----|------|-------|--------------------|--------|
| TC-SEC-01 | Anti-inyección en objetivos | `urls=["a.com; rm -rf /"]`, `` `whoami`.com `` , `$(id).com` | `ValidationError` (rechazado) | ✅ |
| TC-SEC-02 | Límite de objetivos | Lista > 50 URLs | `ValidationError` (máximo 50) | ✅ |
| TC-SEC-03 | Severidades Nuclei | `severities=["bogus"]` | Rechazado; solo info/low/medium/high/critical | ✅ |
| TC-SEC-04 | Secretos no en repo | Auditoría de working tree e historial | `.env` ignorado y nunca commiteado; sin claves | ✅ |

## 7. Degradación elegante

| ID | Caso | Condición | Resultado esperado | Estado |
|----|------|-----------|--------------------|--------|
| TC-DEG-01 | Nuclei sin binario | `nuclei` no instalado | Lista vacía + WARNING, no crashea | ✅ |
| TC-DEG-02 | Objetivo inalcanzable | Host caído/timeout | Scanner devuelve sin abortar el resto | ✅ |

---

## Resumen
- **542/542** tests automáticos en verde.
- **8 scanners** validados E2E contra objetivos reales; **1 defecto** (TC-WS-02) encontrado y **corregido con regresión**.
- Observación menor abierta: TC-UI-05 (estado «Cargando…» cosmético).

> Este cuaderno es una checklist de aceptación estable; los detalles de bajo nivel
> viven en la suite `pytest`. Actualizar al añadir scanners o cambiar el protocolo WS.
