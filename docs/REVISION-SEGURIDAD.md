# Revisión de seguridad y QA — CyberHound Pro

> Fecha: **2026-06-14** · Alcance: backend (`cyberhound/`) + UI (`cyberhound/ui`).
> Rol: QA + CISO. Resultado: **suite 560 verde, ruff limpio**, 2 hallazgos
> corregidos, exposición **solo interna** verificada.

## 1. QA

- **Tests**: `pytest` → **560 pasan** (incluye 10 nuevos de hashing de contraseñas).
  Nota: la imagen de producción no trae `pytest`; la suite se ejecuta en un venv
  con las dependencias correctas (`cryptography>=42`, `asyncssh`).
- **Lint**: `ruff check cyberhound` → sin errores.
- **UI**: navegación responsive sin scroll lateral (1920→390px), de-emoji estilo
  Apple, fix de cabecera de Historial, botón API funcional. Ver
  `REDISENO-NAVEGACION.md`.

## 2. Hallazgos corregidos

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | **Media** | Contraseñas con **SHA-256 sin sal** (rápido → fuerza bruta/rainbow tables). | `core/passwords.py` con **PBKDF2-HMAC-SHA256** (600k iter, sal 16B), comparación constante. **Retrocompatible** (verifica hashes antiguos; re-hash al cambiar contraseña). Cableado en auth/config/API. 10 tests. |
| 2 | **Media** | Botón **API** abría un Swagger en blanco: cargaba CSS/JS de `cdnjs.cloudflare.com` → bloqueado por CSP **y egress a internet** (la app es solo interna). | Swagger UI **vendorizado** en `/static/vendor/` (sin CDN). Compatible con CSP estricta y sin salida a internet. |

## 3. Verificado correcto (sin cambios)

- **Sin inyección de comandos**: 0 usos de `shell=True`, `os.system`, `os.popen`.
- **Exposición SOLO interna**: el dominio se resuelve únicamente por DNS interno
  hacia un reverse proxy en la LAN que reenvía al contenedor; **no** se publica por
  túnel ni en DNS público (los resolvers públicos no devuelven registro). El
  servicio no es alcanzable desde fuera de la red.
- **Auth**: JWT HS256 con secreto persistente (aviso si falta); login con
  **rate-limiting** (5/15 min + bloqueo), **CSRF** en el formulario, comparaciones
  de tiempo constante. Cookie de sesión por defecto; redirección a `/login`.
- **MFA**: TOTP disponible (cifrado en reposo).
- **Cabeceras**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Cache-Control: no-store`, **CSP** (`default-src 'self'`).
- **WS**: validación de mensajes (suite `test_ws_message_validation`).

## 4. Recomendaciones pendientes (no bloqueantes)

| Prioridad | Recomendación |
|---|---|
| Baja | CSP permite `'unsafe-inline'` en `script-src` (necesario por los `onclick` inline). Mejora futura: nonce/hash + quitar inline. |
| Baja | Rehash transparente al primer login para migrar el hash del admin de SHA-256 a PBKDF2 (hoy se migra al cambiar la contraseña). |
| — | Limpieza menor: `id="history-trend-wrap"` duplicado en el panel de Historial. |

## 5. Persistencia / despliegue

Los cambios (UI + backend) están **commiteados en git (local, sin push)** y
desplegados en caliente al contenedor con `docker cp` + `docker restart`
(sobreviven a restart/reboot). Para hacerlos **permanentes ante un recrear/rebuild**
del contenedor hay que **reconstruir la imagen** `cyberhound-pro` y recrear el
contenedor con la **misma** config de compose/Caddy → el dominio interno sigue
igual. (Recomendado coordinarlo por la sensibilidad del acceso.)

## 6. QA exhaustivo del frontend (addendum)

Los tests de `pytest` son de backend y no cubrían el render del front; eso dejó
pasar varios bugs **funcionales** (funciones JS invocadas pero inexistentes). Se
hizo una auditoría completa (navegador headless: toda función de handler +
navegación de los 20 paneles y 14 pestañas de config; análisis estático de
llamadas; simulación de los 12 scanners) y se corrigieron:

| Bug (pre-existente) | Efecto | Fix |
|---|---|---|
| `renderSummary`/`appendAuditRow` sin prefijo `_`; falta `_appendMalwareRow` | Los hallazgos no se mostraban en el panel, solo en el feed de actividad | Llamadas corregidas a `_renderSummary`/`_appendAuditRow` + se crea `_appendMalwareRow` |
| `loadSuppresions` (typo) | Panel de Supresiones y carga de Configuración fallaban | Nombre unificado a `loadSuppressions` |
| `saveAgentConfig` inexistente (sin endpoint) | El botón "Guardar" del modo agente no hacía nada | Endpoint `GET/POST /api/config/agent` (la clave nunca se devuelve) + funciones front + 4 tests |
| `id` duplicado `history-trend-wrap`/`-chart` | DOM inválido (markup muerto) | Bloque duplicado eliminado |

**Red de seguridad permanente:** `tests/test_frontend_integrity.py` comprueba en
la suite normal que toda función de handler existe, que no hay desajuste
`_func`/`func`, que no hay ids duplicados y que los cargadores `load*` existen —
habría cazado todos estos bugs. Estado: **suite 568 verde, ruff limpio**.
