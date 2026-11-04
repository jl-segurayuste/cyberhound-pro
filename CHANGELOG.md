# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versiones según
[SemVer](https://semver.org/lang/es/). Cada versión publicada tiene su etiqueta `vX.Y.Z` y su
release en GitHub, con la imagen Docker correspondiente en GHCR.

## [Sin publicar]

### Corregido
- Reglas YARA: las cuatro URLs de «Actualizar reglas» daban 404 (ficheros movidos en la rama principal)
  y la actualización fallaba siempre. Ahora: webshells de Yara-Rules, puertas traseras y ransomware de
  Linux de Elastic y mineros (*community*), fijados a un commit (670 reglas que compilan juntas).
- Quitada la «actualización semanal de reglas YARA» del scheduler: dependía de una opción que no existía
  y nunca se programaba.

### Documentación
- README: número de tests y versiones de Python del CI, `scap_baseline` en la arquitectura, ruta por
  defecto del certificado (`CH_TLS_DIR`). Manual: YARA y el caso «arranca en HTTP».
- Capturas del README y del manual regeneradas con la interfaz actual (nuevas pestañas de
  Configuración y ámbito por organización). Nuevo `scripts/e2e/capturas.py` para rehacerlas.

## [6.8.3] — 2026-11-04

### Corregido
- Importación XCCDF/OpenSCAP: la remediación de las reglas con `<fixtext>` (sin `<fix>`) se perdía,
  porque un elemento XML sin hijos se evalúa como falso. Ahora se extrae (test de regresión).
- Importación JSON: un `"findings": null` o `"source_host": null` rompía la importación; se tratan
  como vacíos.
- CSRF (login y formularios): un token enviado como fichero provocaba un error 500 en vez de un 403.
- Ticketing: una cancelación (`CancelledError`) se trataba como ticket creado.
- AWX/AAP: con `verify_ssl` activo se pasaba `ssl=None` a aiohttp; ahora se verifica con el contexto
  por defecto.
- Un comando que agota el timeout se recoge tras matarlo (quedaba como proceso zombi).
- Rollback: una acción guardada sin ruta o sin comando se informa como no reversible en vez de fallar.

### Cambiado
- Claves tipadas de aiohttp (`web.AppKey`/`web.RequestKey`, en `cyberhound/core/web_keys.py`) en
  lugar de cadenas en `app[...]` y `request[...]`; los tests fallan si vuelve a aparecer una cadena.
- Las redirecciones que ponen o quitan cookies devuelven una respuesta 302 en vez de un `HTTPFound`
  (devolver la excepción está obsoleto en aiohttp).
- `asyncio.get_running_loop()` en lugar de `get_event_loop()`; `datetime.fromtimestamp(..., UTC)` en
  los logs JSON (mismo formato).
- La suite ya no oculta los `DeprecationWarning`: 0 avisos en Python 3.11, 3.12 y 3.14 (antes 259).

### CI
- mypy bloqueante (0 errores; antes 39 y `|| true`), con las dependencias instaladas para que vea los
  tipos reales.

## [6.8.2] — 2026-11-04

### Seguridad
- Los informes XML importados (Nessus, XCCDF/OpenSCAP) se leen con `defusedxml`: un fichero con
  entidades o DTD se rechaza con un error claro en vez de procesarse.

### Corregido
- En servidores con FIPS activado, `hashlib.md5()`/`sha1()` fallan si no se indica
  `usedforsecurity=False`: la vigilancia de ficheros críticos (eBPF) y los IDs de hallazgos de nuclei
  dejaban de funcionar. Solo se usan para detectar cambios e identificar, no para seguridad.
- Sustituidas APIs obsoletas: `aiohttp.BasicAuth` (Wazuh, Jira, ServiceNow) por la cabecera
  `Authorization` con `aiohttp.encode_basic_auth()`, y `datetime.utcnow()` en los tokens.

### CI
- Bandit pasa a bloquear el pipeline (antes terminaba en `|| true`); los falsos positivos quedan
  marcados con `# nosec` y su motivo.
- Tests también en Python 3.13 y 3.14, ejecución semanal programada y la imagen solo se publica en
  `push` (no en las ejecuciones programadas ni manuales).

## [6.8.1] — 2026-11-01

### Seguridad
- `constraints.txt` (el que usa `install.sh`) fijaba versiones con vulnerabilidades conocidas: PyJWT
  2.13.0 (15), aiohttp 3.14.1 (14), cryptography 49.0.0 (2), asyncssh 2.23.1, dnspython 2.8.0 y
  multidict 6.7.1. Regenerado con las versiones actuales (pip-audit: sin vulnerabilidades conocidas) y
  subidos los mínimos de `pyproject.toml` a versiones corregidas: PyJWT 2.15, aiohttp 3.14.4,
  cryptography 50.0, asyncssh 2.24, dnspython 2.9 y multidict 6.9.1. La imagen Docker no usaba el
  lockfile y ya instalaba versiones corregidas.

## [6.8.0] — 2026-10-31

### Añadido
- **Bastionado CCN-STIC y DISA STIG** (panel Red › *Bastionado de servidores Linux*, tarea WS `scap`):
  auditoría por SSH con los perfiles oficiales de SCAP Security Guide, ejecutando `oscap` en el
  servidor con el contenido de su propia versión. Perfiles CCN-STIC básico, intermedio y avanzado
  (CCN-STIC-610A22, RHEL 9 y derivadas) y DISA STIG (RHEL 8 y 9 y derivadas; con la categoría CAT I,
  II o III de cada regla). Un hallazgo por regla que falla y un resumen con el porcentaje de
  cumplimiento; cuentan para ENS (op.exp.2), PCI-DSS y CIS.
- Corrección remota regla a regla con la corrección oficial de SSG, deshacer (copia de `/etc` antes;
  se guarda solo lo que cambió) y **confirmación obligatoria** (`confirm: true` en `/api/fix/remote`)
  para las reglas que pueden cortar el acceso de administración.

### Corregido
- `oscap xccdf generate fix --rule` ignora `--rule` (oscap 1.3) y devuelve el script del perfil
  entero: ahora se extrae el bloque de la regla y solo ese, y si no se puede aislar exactamente uno no
  se ejecuta nada. Visto en las pruebas antes de publicar: corregir una regla aplicaba las 140 del
  perfil.
- En Rocky y AlmaLinux se usa su propio contenido SCAP (`ssg-rl8`, `ssg-almalinux9`): con el de RHEL
  todas las reglas salen «no aplica». Una evaluación sin ninguna regla aplicable es un error, no un 0 %.
- El fix remoto registraba una acción calculada aparte de la que se ejecutaba.
- El resumen de cumplimiento (hallazgo `passed`) ya no cuenta como control fallido en el informe de
  cumplimiento.

## [6.7.0] — 2026-10-21

### Añadido
- **Verificación de la clave de host SSH (TOFU)**: la primera conexión a cada equipo guarda su clave
  y las siguientes tienen que presentar la misma; si cambia, CyberHound no se conecta (estado "clave de
  host cambiada") y no envía la contraseña ni el script. Configuración › Credenciales SSH lista las
  claves conocidas de la organización y permite olvidar una (`/api/config/ssh-host-keys`) cuando el
  cambio es legítimo, por ejemplo tras reinstalar el equipo. BD v9.

### Corregido
- Las conexiones SSH no verificaban la clave del host (`known_hosts=None`): quien suplantara un equipo
  en la red recibía la contraseña guardada o el script que se ejecuta con sudo.
- El aviso de clave de host no verificable nunca se mostraba: `HostKeyNotVerifiable` es subclase de
  `DisconnectError` y se capturaba antes como "inalcanzable".

## [6.6.0] — 2026-10-21

### Añadido
- **Credenciales SSH guardadas** (Configuración › Credenciales SSH y `/api/config/ssh-credentials`):
  un par ed25519 que genera CyberHound (se muestra la clave pública para `authorized_keys`), una clave
  privada pegada (también con frase de paso) o una contraseña. Se guardan cifradas con una clave
  derivada de `auth.secret` y de la organización, y la API nunca devuelve el secreto. Se eligen en el
  panel Red para auditar, corregir y deshacer fixes remotos.
- **Auditoría SSH programada**: la tarea `ssh` en Programados, con una credencial guardada; un
  análisis de red programado con credencial audita además por SSH los equipos que encuentra.
- **Playbook de remediación nuevo**: un play por host (los hallazgos remotos, en su host), el mismo
  catálogo que los fixes de CyberHound en módulos FQCN, y lo que no se puede automatizar como
  comentario al principio. En sshd cambia todas las líneas de la sección global y de
  `sshd_config.d/*.conf`, valida con `sshd -t` y no toca los bloques `Match`.
- La batería E2E levanta un servidor SSH local de pruebas y audita por SSH de verdad con las
  credenciales guardadas, a mano y programado.

### Cambiado
- `asyncssh[bcrypt]`: hace falta para las claves OpenSSH protegidas con frase de paso.
- En modo local, Ansible solo corrige los hallazgos del propio servidor.
- «▶ Ahora» en Programados se desactiva mientras la programación está en curso.

### Corregido
- Una organización que entraba por SSH con usuario y contraseña podía acabar autenticada con las
  claves por defecto del servidor (`~/.ssh/id_*`) o su agente.
- El playbook descargable ejecutaba con `shell` y `become` el texto de remediación del hallazgo, que
  en los remotos escribe el host auditado; y el título se pegaba en el YAML, donde una plantilla
  `{{ … }}` se evaluaba en la máquina de control.
- El modo local de Ansible aplicaba en el servidor las correcciones de hallazgos de otros hosts.
- Las tareas de sshd del playbook no surtían efecto si el valor inseguro estaba en una línea anterior
  o en `sshd_config.d`; los parámetros sysctl locales nunca generaban tarea.
- Una contraseña SSH incorrecta se informaba como "host inalcanzable".
- **sshd, auditoría y fix (local y remoto)**: se leía y cambiaba solo `sshd_config`. Ahora se usa el
  valor efectivo (primer valor, con los `Include` de `sshd_config.d` y sin los bloques `Match`), el fix
  cambia todas las líneas globales de la opción en esos ficheros, añade la que falta antes del primer
  `Match` (antes al final, dentro del último bloque), valida con `sshd -t` y comprueba que el valor
  efectivo queda bien; si no, lo restaura. Deshacer devuelve cada fichero a como estaba (los fixes
  guardados con versiones anteriores se siguen pudiendo deshacer).
- Los scripts remotos no funcionaban con Python 3.6 (RHEL 8): `subprocess.run(capture_output=…)` y
  `str.removesuffix` son de 3.7 y 3.9. El fix remoto fallaba siempre y la auditoría se saltaba sin
  avisar los checks que lanzan comandos (servicios, ficheros con permisos de escritura para todos, ufw).
- `docs/REDISENO-NAVEGACION.md` daba por pendientes dos cosas ya resueltas (CSP con nonce e id duplicado).

## [6.5.0] — 2026-10-21

### Añadido
- **Sesiones revocables.** Cada login crea una sesión en la BD (el JWT lleva su `jti`): salir,
  cambiar la contraseña o que un administrador desactive al usuario la invalida al momento.
  Antes la cookie robada seguía valiendo hasta caducar (8 h).
- **Mi cuenta** (Configuración): cambiar la propia contraseña, ver las sesiones abiertas y
  cerrarlas, y crear tokens de API.
- **Tokens de API** (`Authorization: Bearer cht_…`): con rol tope (nunca más que el del usuario),
  caducidad y último uso. Solo se guarda su hash y no sirven para gestionar credenciales.
- **Registro de auditoría** (`/api/audit` y pestaña Auditoría): logins y sus fallos, usuarios,
  contraseñas, 2FA, tokens, fixes remotos y cambios de configuración, con filtros.
- **Ámbito de análisis por organización**: el superadmin fija qué redes, IPs y dominios puede
  analizar cada organización. Sin ámbito, ninguno. Se rechazan los dominios que resuelven a una
  IP interna fuera del ámbito.
- **Integraciones por organización**: cada una configura su correo, webhook, SIEM y Jira/ServiceNow.
  Sus destinos deben ser públicos o estar dentro de su ámbito (protección SSRF, comprobada al
  guardar y antes de cada envío).
- **Análisis programados** (`/api/schedules` y pestaña Programados): red, cabeceras web,
  exposición, API, TLS, DNS, subdominios o Nuclei a la hora y los días elegidos, por organización.
- **Deshacer fixes remotos**: al aplicar un fix por SSH se guarda el estado previo del host
  (línea de `sshd_config`, valor de sysctl, servicio, permisos, ufw) y se puede volver atrás
  desde la pestaña Fixes remotos o el propio botón.
- **Migraciones versionadas en PostgreSQL**, como en SQLite. Antes una tabla o una columna nueva
  no llegaba a las instalaciones existentes.

### Cambiado
- Desactivar el 2FA exige un código válido.
- Las tareas del scheduler de la plataforma desactivadas en `config.yaml` también se crean (antes
  no se podían activar desde la UI) y el interruptor se guarda en `config.yaml`.
- `server.py` y `app.js` partidos por áreas (`cyberhound/api/handlers/`, `cyberhound/ui/static/js/`);
  la UI ya no sobrescribe funciones en tiempo de ejecución.
- El lint de CI (ruff) incluye `tests/`.

### Corregido
- Guardar notificaciones o SIEM en caliente perdía el servidor y el usuario SMTP, las credenciales
  de la API de Wazuh y de Elasticsearch, y el índice de Splunk; no se aplicaban hasta reiniciar.
- Una organización podía usar la clave SSH de la plataforma, o cualquier ruta de clave del
  servidor, para entrar en sus hosts.
- Lo que el superadmin hacía con su propia cuenta mientras miraba una organización se auditaba en
  la organización y no en la plataforma.
- Las notificaciones del navegador para hallazgos críticos nunca saltaban: su manejador no estaba
  conectado al canal push.
- Descubrir red sin indicar redes en una organización usaba las del propio servidor; ahora pide las redes.

## [6.4.0] — 2026-10-20

### Añadido
- Multi-tenant real: BD por organización (fichero SQLite o esquema PostgreSQL), login por
  organización, superadmin que puede mirar cualquiera y rutas que tocan el servidor reservadas
  a la plataforma.
- Suite E2E en navegador (`scripts/e2e/run.sh`): cada panel en tres tamaños, cada botón, roles,
  multi-tenant y análisis reales contra objetivos controlados.

### Corregido
- Seguridad: bypass del 2FA, inyección en el fix remoto, script remoto en `/tmp` ejecutado con
  sudo, fix local de hallazgos remotos, XSS en el informe HTML, TOTP guardado en claro, `/metrics`
  público tras un proxy y contraseña por defecto.
- Intel no funcionaba de punta a punta; lo guardado desde la UI se perdía en Docker; PostgreSQL
  nunca llegaba a activarse; `docker-compose`, el entrypoint e `install.sh` tenían fallos.

### Eliminado
- Planes y licencias: se podían falsificar y no limitaban nada.

Las versiones anteriores no tienen registro de cambios; su historia está en `git log`.

[6.8.3]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.8.3
[6.8.2]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.8.2
[6.8.1]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.8.1
[6.8.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.8.0
[6.7.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.7.0
[6.6.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.6.0
[6.5.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.5.0
[6.4.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.4.0
