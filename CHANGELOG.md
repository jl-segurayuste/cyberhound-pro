# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versiones según
[SemVer](https://semver.org/lang/es/). Cada versión publicada tiene su etiqueta `vX.Y.Z` y su
release en GitHub, con la imagen Docker correspondiente en GHCR.

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

[6.7.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.7.0
[6.6.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.6.0
[6.5.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.5.0
[6.4.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.4.0
