# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versiones según
[SemVer](https://semver.org/lang/es/). Cada versión publicada tiene su etiqueta `vX.Y.Z` y su
release en GitHub, con la imagen Docker correspondiente en GHCR.

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

[6.5.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.5.0
[6.4.0]: https://github.com/jl-segurayuste/cyberhound-pro/releases/tag/v6.4.0
