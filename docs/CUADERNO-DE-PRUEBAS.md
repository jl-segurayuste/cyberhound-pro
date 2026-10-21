# Cuaderno de pruebas — CyberHound Pro

Checklist de aceptación que **complementa** la suite automática. Se ejecuta antes de publicar una
versión; casi todo está automatizado en [`scripts/e2e/`](../scripts/e2e/README.md).

- **Última ejecución:** 2026-10-21 · v6.6.0 · `master`
- **Entorno:** Ubuntu 24.04, Python 3.12, Chromium (Playwright), SQLite y PostgreSQL 16; Docker 27 para el stack de producción
- **Resultado global:** ✅ Apto — ver la [revisión de seguridad](REVISION-SEGURIDAD.md#9-revisión-de-2026-10-21-v660-credenciales-ssh-y-playbooks-de-ansible) para lo encontrado y corregido en esta ronda

Leyenda: ✅ pasa · ⚠️ pasa con observación · ❌ falla

## 1. Suite automática

| ID | Qué | Cómo | Resultado | Estado |
|----|-----|------|-----------|--------|
| TC-AUTO-01 | Tests unitarios, de integración y de coherencia (SQLite) | `pytest tests/` | 736 pasan (1 omitido: solo PostgreSQL) | ✅ |
| TC-AUTO-02 | La misma suite contra PostgreSQL 16 | `CH_DB_URL=postgresql://… pytest tests/` | 737 pasan | ✅ |
| TC-AUTO-03 | Lint | `ruff check cyberhound tests` | sin avisos | ✅ |
| TC-AUTO-05 | Migración de una BD 6.5.0 (v7) a v8 | BD creada con el código publicado y abierta con el nuevo, en SQLite y PostgreSQL | Los programados se conservan y admiten credencial | ✅ |
| TC-AUTO-06 | Playbook con `ansible-playbook` real | Contenedor Debian 12 con sshd, drop-in de cloud-init y un bloque `Match` | `sshd -T` con valores seguros, `Match` intacto, 2ª pasada `changed=0` | ✅ |
| TC-AUTO-04 | CI | GitHub Actions: lint, Python 3.11 y 3.12, PostgreSQL, análisis de seguridad, imagen | verde | ✅ |

## 2. Interfaz (navegador real) — `scripts/e2e/ui.py`

| ID | Caso | Resultado esperado | Estado |
|----|------|--------------------|--------|
| TC-UI-01 | Los 19 paneles en escritorio (1440×900), tablet (1024×768) y móvil (390×844) | Sin desbordamiento horizontal; scroll vertical cuando el contenido lo pide | ✅ 57 paneles×viewport |
| TC-UI-02 | Menú: cada entrada abre su panel; botón ☰ en móvil | Panel activo correcto | ✅ |
| TC-UI-03 | Un clic en cada botón, selector, fila y pestaña de Configuración | Sin errores JS ni de consola, sin 5xx ni peticiones fallidas | ✅ 203 controles |
| TC-UI-04 | Cabecera: búsqueda global, Log, API (Swagger), Salir | Funcionan; tras salir la API pide sesión | ✅ |
| TC-UI-05 | Incidencias esperadas | Intel sin API keys (400 claro), el admin no puede quitarse su rol (400), SBOM aún no generado (404), guardar una credencial SSH sin nombre (400) | ✅ |

## 3. Roles — `scripts/e2e/roles.py`

| ID | Caso | Resultado esperado | Estado |
|----|------|--------------------|--------|
| TC-ROL-01 | Lector recorre y pulsa todo | Ningún 403; lo no permitido aparece bloqueado y solo avisa | ✅ |
| TC-ROL-02 | Operador | Solo bloqueado lo de configuración | ✅ |
| TC-ROL-03 | Pestaña Usuarios | Oculta para quien no es admin | ✅ |

## 4. Multi-tenant — `scripts/e2e/multitenant.py` + `tests/test_multitenancy_isolation.py`

| ID | Caso | Resultado esperado | Estado |
|----|------|--------------------|--------|
| TC-MT-01 | El superadmin crea una organización desde la UI | Aparece en la tabla y en el selector; se muestra su clave de agente | ✅ |
| TC-MT-02 | Cambiar de organización con el selector | Ve sus datos (vacíos) y al volver los de la plataforma | ✅ |
| TC-MT-03 | La admin de la organización entra con el campo Organización | Sin menú Sistema ni Monitor ni pestañas de plataforma; ve su clave de agente | ✅ |
| TC-MT-04 | Pulsar todo como admin de la organización | Ningún 401/403/500 ni error JS | ✅ |
| TC-MT-05 | Baja desde la UI | Corta su sesión al instante | ✅ |
| TC-MT-06 | Aislamiento (datos, usuarios, supresiones, agentes, caché, push, rutas de plataforma, WS, reutilización del identificador, 2FA, tokens, programados, fixes remotos, credenciales SSH) | Nada cruza de una organización a otra, en SQLite y PostgreSQL | ✅ 22 escenarios |
| TC-MT-07 | Ámbito desde la UI: el superadmin fija redes y dominios; la organización programa dentro y fuera | Dentro se guarda; fuera se rechaza con el motivo; sin ámbito no analiza nada; un dominio que resuelve a la LAN se rechaza | ✅ |
| TC-MT-08 | Integraciones de la organización | Las suyas, sin tocar las de la plataforma; destinos internos (127.0.0.1, LAN) rechazados | ✅ |

## 5. Funcional contra el backend — `scripts/e2e/functional.py`

Análisis reales sobre **objetivos controlados** que se generan en cada ejecución (`targets.py`: una
webshell, secretos falsos, `shell=True` y una web local con `.git`/`.env` expuestos) y un servidor
SSH local de pruebas (`sshd.py`).

| ID | Área | Casos | Estado |
|----|------|-------|--------|
| TC-F-01 | Seguridad web | Cabeceras (CSP, X-Frame-Options, nosniff), CSRF del login, cookie HttpOnly+Secure+SameSite, `/metrics` | ✅ |
| TC-F-02 | Autenticación | Contraseña errónea, login, usuario creado entra, logout, rate limit con IP real tras proxy | ✅ |
| TC-F-03 | RBAC | El lector no configura ni crea usuarios pero sí lee; el admin no se quita su rol | ✅ |
| TC-F-04 | WebSocket | Tarea no permitida e inyección en URLs rechazadas | ✅ |
| TC-F-05 | Análisis | Hardening, malware (encuentra la webshell), código (encuentra los secretos), Docker sin Docker, servicios, TLS (autofirmado), cabeceras y exposición web (encuentra `.git`/`.env`), API/CORS, Nuclei sin binario, DNS, subdominios, red, intel | ✅ |
| TC-F-06 | API | Historial, comparación, score, panel, activos, supresiones, usuarios, scheduler, configuración, agentes (clave buena y mala), informes (HTML, Ansible, **PDF real**), compliance, OpenAPI y Swagger, Ansible, organizaciones, importación, SBOM, YARA, rollback, monitor | ✅ |
| TC-F-07 | Cuarentena | Aislar (el original desaparece), listar, restaurar íntegro, borrar | ✅ |
| TC-F-08 | 2FA de principio a fin | Setup, código erróneo, activar, solo contraseña no entra, contraseña+código sí, desactivar | ✅ |
| TC-F-10 | Mi cuenta | Sesiones listadas sin su id interno; contraseña actual errónea rechazada | ✅ |
| TC-F-11 | Tokens de API | Autentica con su rol, no lo supera, no gestiona credenciales, se lista sin hash, revocado deja de valer | ✅ |
| TC-F-12 | Auditoría | Registra el login; el filtro de fallos solo devuelve fallos | ✅ |
| TC-F-13 | Integraciones en caliente | El servidor SMTP guardado se aplica sin reiniciar; la contraseña no se devuelve | ✅ |
| TC-F-14 | Programados | Crear, rechazar tareas no programables, lanzar ahora, su análisis queda en el historial, pausar, borrar | ✅ |
| TC-F-15 | Credenciales SSH | Contraseña y par generado (sin devolver el secreto), clave inválida rechazada; la clave generada no entra hasta autorizarla y después audita por SSH real; credencial inexistente rechazada | ✅ |
| TC-F-16 | Programado SSH | Sin credencial rechazado; con credencial se ejecuta y deja hallazgos reales; la credencial en uso no se borra; último uso registrado | ✅ |
| TC-F-17 | Playbook de Ansible | Un play por host y nada del texto del hallazgo (ni comandos ni plantillas `{{ }}`) | ✅ |
| TC-F-09 | Robustez | Ninguna respuesta 5xx en toda la API | ✅ |

Resultado: **163/163** pruebas.

## 6. Despliegue

| ID | Caso | Resultado esperado | Estado |
|----|------|--------------------|--------|
| TC-DEP-01 | Imagen Docker, volumen nuevo y sin `CH_PASSWORD` | Arranca sana, genera la contraseña (solo en el log), PBKDF2, certificado en `/data/tls` | ✅ |
| TC-DEP-02 | `docker-compose.production.yml` completo | postgres, app, certs, nginx y backup sanos; login y análisis por WebSocket a través de nginx; datos en PostgreSQL; copia creada; HTTP→HTTPS conserva el puerto | ✅ |
| TC-DEP-03 | `install.sh` en Ubuntu 24.04 y Debian 12 (contenedores limpios) | Instala, la contraseña mostrada entra, sin `.git` en `/opt` | ✅ |
| TC-DEP-04 | Actualización de una instancia existente (homelab) | Conserva configuración y datos; versión nueva en `/health`; detrás de Caddy, `/metrics` pide sesión | ✅ |

---

> Al añadir un análisis, una pestaña o cambiar el protocolo WS, actualiza `scripts/e2e/` y este cuaderno.
