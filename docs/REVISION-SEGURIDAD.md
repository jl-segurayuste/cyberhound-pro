# Revisión de seguridad y QA — CyberHound Pro

> Revisión inicial: **2026-06-14** (§1-6) · Última revisión: **2026-10-20** ([§7](#7-revisión-de-2026-10-20-qa-de-extremo-a-extremo--seguridad)).
> Alcance: backend (`cyberhound/`) + UI (`cyberhound/ui`).
> Rol: QA + CISO. Resultado de 2026-06-14: **suite 560 verde, ruff limpio**, 2 hallazgos
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

- **Sin inyección de comandos**: 0 usos de `shell=True`, `os.system`, `os.popen`. *(Corrección 2026-10-20: la corrección remota sí ejecutaba por SSH texto del host auditado, ver §7.)*
- **Exposición SOLO interna**: el dominio se resuelve únicamente por DNS interno
  hacia un reverse proxy en la LAN que reenvía al contenedor; **no** se publica por
  túnel ni en DNS público (los resolvers públicos no devuelven registro). El
  servicio no es alcanzable desde fuera de la red.
- **Auth**: JWT HS256 con secreto persistente (aviso si falta); login con
  **rate-limiting** (5/15 min + bloqueo), **CSRF** en el formulario, comparaciones
  de tiempo constante. Cookie de sesión por defecto; redirección a `/login`.
- **MFA**: TOTP disponible. *(Corrección 2026-10-20: el secreto se guardaba en claro; ahora va cifrado, ver §7.)*
- **Cabeceras**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Cache-Control: no-store`, **CSP** (`default-src 'self'`).
- **WS**: validación de mensajes (suite `test_ws_message_validation`).

## 4. Recomendaciones pendientes (no bloqueantes)

| Prioridad | Recomendación |
|---|---|
| ~~Baja~~ ✅ | **HECHO** (2026-10-20): eliminados los 241 manejadores inline (213 en `index.html` + 28 en plantillas de `app.js`); los eventos se declaran con `data-on-<evento>` y los atiende un dispatcher delegado en fase de captura (respeta el orden y el `stopPropagation` de antes). La CSP pasa a `script-src-attr 'none'`: ni un atributo `on*` inyectado puede ejecutar JS. Cubierto por `test_no_inline_event_attributes` y `test_all_event_handlers_are_defined`. |
| ~~Baja~~ ✅ | **HECHO** (verificado 2026-07-08, `auth.py:269` `passwords.needs_rehash`): rehash transparente al login migra el hash del admin de SHA-256 a PBKDF2 sin esperar a un cambio de contraseña. |
| ~~—~~ ✅ | **HECHO** (verificado 2026-07-08): ya no hay `id="history-trend-wrap"` duplicado; cubierto además por el test automático `test_no_duplicate_element_ids` (`tests/test_frontend_integrity.py`). |

## 5. Persistencia / despliegue

Los cambios (UI + backend) están **commiteados y subidos** al repositorio
remoto. El contenedor corre desde una imagen con el código dentro (sin bind-mount),
así que un cambio no queda desplegado solo por estar en git: hay que
**reconstruir la imagen** `cyberhound-pro` y recrear el contenedor con la
**misma** config de compose/proxy (`docker compose up -d --build`); los datos y
la configuración persisten en el volumen `/data`, y el dominio interno sigue igual.

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


## 7. Revisión de 2026-10-20 (QA de extremo a extremo + seguridad)

Se recorrió la aplicación entera con un navegador real (cada panel en 3 tamaños, cada control, los
roles y el multi-tenant) y una batería funcional contra el backend con análisis reales sobre objetivos
controlados (hoy en `scripts/e2e/`). Además de bugs funcionales (Intel inservible, configuración que se
perdía en Docker, PostgreSQL que nunca se activaba, PDF que no salía…), se encontraron y corrigieron
estos problemas de seguridad, cada uno con su test de regresión:

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | **Crítica** | **Bypass del 2FA**: el token intermedio "contraseña OK, falta el código" se firmaba con el mismo secreto que la sesión y no se miraba su `purpose`: enviándolo como `Bearer` o como cookie de sesión se entraba sin código. | `verify_jwt` rechaza cualquier token con `purpose`. `tests/test_auth_tokens.py`. |
| 2 | **Alta** | **Inyección de comandos en la corrección remota**: se ejecutaba por SSH, tal cual, la remediación que devolvía el host auditado (con nombres de fichero del propio host). Un usuario sin privilegios de ese host podía ejecutar comandos como el usuario SSH (normalmente root) creando un fichero world-writable con `;` en el nombre. | La acción se construye en CyberHound desde el id del hallazgo, con parámetros validados, viaja como dato a un script fijo y se ejecuta sin shell. `tests/test_remote_fix.py`. |
| 3 | **Alta** | **Escalada en la auditoría remota**: el script se escribía en `/tmp` con nombre predecible y luego se ejecutaba con `sudo`; un usuario local podía sustituirlo. | El script va por stdin a `python3 -`; nada en `/tmp`. |
| 4 | **Alta** | **Roles decorativos**: ningún endpoint comprobaba los permisos (un `viewer` podía crear administradores). | Middleware RBAC + la UI desactiva lo no permitido; coherencia UI↔servidor comprobada por test. |
| 5 | **Media** | `/api/fix/local` aplicaba en este servidor el fix de un hallazgo de otro host; `/api/fix/remote` usaba el host de la petición en vez del del hallazgo. | Validado contra `source_host`. |
| 6 | **Media** | Rate limit del login esquivable con `X-Forwarded-For` falso; detrás de un proxy, todos los clientes compartían la IP del proxy (bloqueo de todos a la vez). | IP real solo desde `trusted_proxies` (IP, CIDR o nombre), entrada más a la derecha no confiable. |
| 7 | **Media** | Escrituras en `/api/*` desde otro subdominio del mismo sitio (SameSite no lo cubre). | Rechazo por `Sec-Fetch-Site`/`Origin`. |
| 8 | **Media** | XSS almacenado en el informe HTML descargable: títulos y categorías de hallazgos (que pueden venir de webs o agentes de terceros) sin escapar. | Todo escapado; sin JS en línea. |
| 9 | **Media** | Secreto TOTP en claro en la BD. | Cifrado con Fernet (clave derivada por HKDF del secreto de la instancia); los antiguos se cifran al entrar. |
| 10 | **Media** | Sistema de licencias falsificable (HMAC con la clave publicada en el repo) y sin ningún límite aplicado. | Eliminado: todo es AGPL sin restricciones. |
| 11 | **Baja** | Sin contraseña configurada valía `cyberhound`; el entrypoint de Docker usaba SHA-256 sin sal e interpolaba la contraseña en código Python. | Hash inutilizable por defecto, validación al arrancar, entrypoint con PBKDF2 y valores por entorno. |
| 12 | **Baja** | `/metrics` público también a través de un proxy; rutas públicas por prefijo (`/loginx`). | Sin sesión solo desde el propio host; rutas exactas. |
| 13 | **Baja** | CSP con `unsafe-inline` en atributos de eventos. | 241 manejadores en línea eliminados; `script-src-attr 'none'`. |
| 14 | **Baja** | Activar ufw desde un fix podía dejar fuera al administrador remoto. | Abre antes SSH y el puerto de la web. |
| 15 | **Baja** | `/api/intel/*` metía los objetivos sin validar en las URLs de las APIs externas. | Validación de IP/dominio/hash/email. |

Multi-tenant (nuevo): cada organización tiene su propia BD (fichero SQLite o esquema PostgreSQL), la
sesión queda ligada a ella, las cachés en memoria y las notificaciones push se separan, y lo que actúa
sobre el propio servidor queda reservado al superadmin. `tests/test_multitenancy_isolation.py` cubre
datos, usuarios, supresiones, agentes, caché de hallazgos, push, rutas de plataforma, baja y reutilización
del identificador, en SQLite y en PostgreSQL.

## 8. Revisión de 2026-10-21 (v6.5.0: cuentas, organizaciones y deshacer)

Al añadir sesiones revocables, tokens de API, auditoría, ámbito e integraciones por organización,
análisis programados y deshacer fixes remotos se encontraron y corrigieron estos problemas, cada uno
con su test de regresión:

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | **Alta** | **Sin ámbito en multi-tenant**: cualquier organización podía escanear (red, SSH, web, LDAP) la LAN del propio servidor o las redes de otros clientes. | Redes y dominios permitidos por organización (vacío = ninguno), comprobados en cada análisis, descubrimiento, LDAP, fix remoto y programado; un dominio permitido que resuelve a una IP interna fuera del ámbito se rechaza. `tests/test_scope.py`, `test_ambito_de_analisis_por_organizacion`. |
| 2 | **Alta** | **Clave SSH de la plataforma al alcance de las organizaciones**: el análisis SSH y el fix remoto usaban por defecto `scan.ssh_key_path`, o la ruta de clave que mandara la petición. | En una organización no se usa ninguna clave del servidor; solo usuario y contraseña. |
| 3 | **Media** | **Sesiones irrevocables**: salir o cambiar la contraseña solo borraba la cookie; un JWT copiado valía hasta caducar (8 h). | Tabla de sesiones (`jti`) comprobada en cada petición. `tests/test_sessions_tokens.py`. |
| 4 | **Media** | **2FA desactivable sin código**: con una sesión robada bastaba una petición para quitarlo. | Exige un código TOTP o de recuperación válido. |
| 5 | **Media** | **SSRF por integraciones** (al abrirlas a las organizaciones): webhook, SIEM o Jira apuntados a `127.0.0.1` o a la LAN harían que el servidor enviara peticiones por el tenant. | Destinos públicos o dentro del ámbito, comprobados al guardar y antes de cada envío. `tests/test_integrations.py`. |
| 6 | **Media** | **Integraciones compartidas**: todas las organizaciones enviaban sus hallazgos al SIEM, Jira y correo de la plataforma. | Cada organización tiene las suyas. |
| 7 | **Baja** | **Estado previo del host sin validar** al guardar cómo deshacer un fix remoto (viene del host auditado). | Solo se aceptan valores con forma conocida (misma directiva de sshd, valor de sysctl sin metacaracteres, modo octal, booleanos). |
| 8 | **Baja** | Lo que el superadmin hacía con su cuenta mirando una organización se auditaba en la organización. | Se audita en la plataforma. |

Además se arreglaron bugs funcionales: la recarga en caliente de notificaciones y SIEM perdía campos
(servidor SMTP, credenciales de Wazuh/ELK, índice de Splunk), el interruptor del scheduler no se
guardaba y las notificaciones del navegador para críticos nunca saltaban (el manejador no estaba
conectado al canal push).

## 9. Revisión de 2026-10-21 (v6.6.0: credenciales SSH y playbooks de Ansible)

Al añadir las credenciales SSH guardadas (y con ellas los análisis SSH programados) y rehacer el
generador de playbooks se encontraron y corrigieron estos problemas, cada uno con su test:

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | **Alta** | **Claves SSH del servidor con contraseña de una organización**: con usuario y contraseña, asyncssh prueba antes las claves de `~/.ssh/id_*` y el agente del proceso. Si un host del ámbito de la organización confiaba en esa clave, entraba con la identidad de la plataforma aunque la contraseña fuera incorrecta. Además `client_keys=[]` no lo evita: también carga las de por defecto. | En una organización `client_keys=None` y sin agente: solo su contraseña o su credencial guardada. `test_una_organizacion_no_entra_con_la_clave_de_la_plataforma` (servidor SSH real en el test). |
| 2 | **Alta** | **El playbook descargable ejecutaba la remediación del hallazgo**: `ansible.builtin.shell` con la primera línea de la remediación, `become` y `hosts: all`. En los hallazgos remotos ese texto lo escribe el host auditado. | El export usa el generador nuevo: tareas solo del catálogo de CyberHound, nunca texto del hallazgo. `tests/test_ansible_playbook.py`. |
| 3 | **Alta** | **Inyección de plantillas en el playbook**: el título del hallazgo iba a un f-string del YAML (`name:` y `debug`). Una comilla rompía el YAML y un `{{ lookup('pipe', …) }}` en el título de un hallazgo remoto se ejecutaba en la máquina de control (el propio servidor en modo local). | Playbook construido como datos y volcado con el `SafeDumper` de PyYAML; rutas, servicios, usuarios y hosts validados; lo manual va en comentarios de una sola línea. |
| 4 | **Media** | **El modo local de Ansible corregía en el servidor los hallazgos de otros hosts** (los cargaba de la BD sin `source_host`). | En modo local solo entran los hallazgos del propio servidor; el resto, por AWX o con el playbook descargado (un play por host). |
| 5 | **Media** | **Las correcciones de sshd del playbook no surtían efecto**: `lineinfile` cambia la última línea, pero sshd usa la primera (Debian trae `X11Forwarding yes` de serie) y lee antes `sshd_config.d/*.conf` (cloud-init deja `PasswordAuthentication yes`). | Se cambian todas las líneas de la sección global y las de `sshd_config.d`, se añade antes del primer `Match` si falta y se valida con `sshd -t`. Probado con `ansible-playbook` real en Debian 12: `sshd -T` da los valores seguros y la segunda pasada no cambia nada. |

Credenciales SSH guardadas: el secreto va cifrado (Fernet) con una clave derivada de `auth.secret` y
del identificador de la organización, así que copiado a la BD de otra organización no se descifra; la
API nunca lo devuelve. Una credencial que usa un programado no se puede borrar.

Además se arreglaron bugs funcionales: los parámetros sysctl locales nunca generaban tarea de Ansible
(se buscaba `kernel_aslr`, que no existe), una contraseña SSH incorrecta se informaba como "host
inalcanzable" (`PermissionDenied` es subclase de `DisconnectError` y se capturaba después) y las claves
OpenSSH con frase de paso no se podían importar (faltaba `bcrypt`).

Después, en la misma versión:

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 6 | **Media** | **El fix de sshd (local y remoto) decía "aplicado" sin surtir efecto** y la auditoría no veía el valor real: solo se leía y cambiaba `sshd_config`, pero un `sshd_config.d/*.conf` (cloud-init deja `PasswordAuthentication yes`) se lee antes y manda; además la opción que faltaba se añadía al final del fichero, dentro del último `Match`. | `core/sshd_config.py`: valor efectivo (primer valor, `Include`, sin `Match`) para auditar; el fix cambia todas las líneas globales en esos ficheros, inserta antes del primer `Match`, valida con `sshd -t`, comprueba el valor efectivo y si no, restaura. El deshacer guarda cada línea cambiada por fichero (validado en el servidor: rutas dentro de `/etc/ssh`, misma opción, línea nueva puesta por CyberHound). `tests/test_sshd_config.py`, `test_fix_ssh_remoto_con_drop_in_y_match`. |
| 7 | **Media** | **Los scripts remotos no funcionaban en RHEL 8** (Python 3.6): `subprocess.run(capture_output=…, text=…)` es de 3.7 y `str.removesuffix` de 3.9. El fix remoto fallaba siempre y la auditoría se saltaba en silencio los checks que lanzan comandos. | API de 3.6 en los dos scripts y un test que lo vigila. Probado en un contenedor `python:3.6`: auditoría, los cinco tipos de fix y su deshacer (sshd vuelve a quedar idéntico). |

## 10. Revisión de 2026-10-21 (v6.7.0: claves de host SSH)

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | **Alta** | **Sin verificación de la clave de host SSH**: todas las conexiones usaban `known_hosts=None`. Quien suplantara un equipo del ámbito (ARP o DNS en la LAN) recibía la contraseña guardada o escrita, y el análisis programado la enviaba cada noche sin nadie delante. | TOFU por organización (`core/ssh_host_keys.py`, BD v9): la primera conexión guarda la clave de host:puerto y las siguientes exigen la misma; si no, se corta antes de autenticar. El administrador ve y olvida claves en Credenciales SSH (auditado). `tests/test_ssh_host_keys.py` con un servidor SSH real que cambia de clave en el mismo puerto, y la E2E hace lo mismo con `sshd.py`. |
| 2 | Baja | El aviso de clave no verificable nunca se mostraba (`HostKeyNotVerifiable` se capturaba antes como `DisconnectError`, "inalcanzable"). | Orden de los `except` corregido; estado `hostkey_changed` con el motivo en el panel Red. |
