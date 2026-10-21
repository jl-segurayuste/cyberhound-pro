# CyberHound Pro

**Plataforma de auditoría, seguridad y monitoreo continuo para PYMEs**

> Analiza tu red, servidores, contenedores, webs y código. Detecta vulnerabilidades, malware y configuraciones inseguras, corrige con un clic (y deshace) y vigila en tiempo real. Una instancia o varias organizaciones aisladas (multi-tenant).

[![Versión](https://img.shields.io/badge/versión-v6.5.0-blue.svg)](cyberhound/__init__.py)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-729%20passed-green.svg)](#tests)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

---

## Índice

- [¿Qué hace?](#qué-hace)
- [Capturas](#capturas)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Usuarios, roles y 2FA](#usuarios-roles-y-2fa)
- [Multi-tenant](#multi-tenant)
- [Funcionalidades](#funcionalidades)
- [Arquitectura](#arquitectura)
- [Checks de hardening](#checks-de-hardening-31-checks)
- [Checks Docker y Kubernetes](#checks-docker-y-kubernetes)
- [API REST y WebSocket](#api-rest-y-websocket)
- [Seguridad implementada](#seguridad-implementada)
- [Integraciones](#integraciones)
- [Configuración](#configuración)
- [Tests](#tests)
- [Roadmap](#roadmap)
- [Licencia](#licencia)

---

## ¿Qué hace?

CyberHound Pro es una herramienta todo-en-uno de ciberseguridad para entornos Linux sin equipo de seguridad dedicado:

| Módulo | Descripción |
|--------|-------------|
| **Hardening** | 31 checks del sistema con corrección automática (y deshacer) de la mayoría |
| **Red** | Descubrimiento (nmap/arp-scan), sistema operativo, CVEs y auditoría SSH de cada host |
| **SSH remoto** | Auditoría de varios hosts en paralelo y corrección remota segura |
| **Malware** | YARA, hashes (VirusTotal/MalwareBazaar), auditd, cron y webshells; cuarentena |
| **Docker + K8s** | 7 checks de Docker + 11 de Kubernetes; análisis de imágenes y de contenedores en vivo |
| **Código** | bandit, shellcheck, eslint y detección de secretos (gitleaks → trufflehog → semgrep → regex) |
| **Web** | TLS/SSL, cabeceras de seguridad, exposición (`.git`, `.env`, backups), API/CORS, Nuclei |
| **DNS** | SPF, DMARC, DKIM, DNSSEC, CAA y subdominios por Certificate Transparency |
| **Threat intel** | Shodan, VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX y Have I Been Pwned |
| **Scoring** | Score contextual 0-100 (A-F) con factor de exposición |
| **Compliance** | ENS, ISO 27001:2022, PCI-DSS v4.0 y CIS Controls v8, con aviso si baja |
| **Monitor** | Procesos y ficheros críticos en tiempo real (eBPF con bpftrace, o auditd) |
| **Integraciones** | SIEM (Wazuh, Elasticsearch, Splunk), Jira/ServiceNow, email/webhooks, AWX, agentes |

---

## Capturas

> Capturas de la interfaz actual tomadas sobre una instancia local con **datos de ejemplo ficticios** (red `10.10.0.0/24`, dominio `ejemplo-demo.es`).

<img src="docs/img/capturas/dashboard.png" alt="Panel de inicio">

<p><img src="docs/img/capturas/login.png" alt="Login" width="420"> <img src="docs/img/capturas/movil.png" alt="Vista móvil" width="200"></p>

Menú de navegación (las secciones se agrupan en Red, Sistema, Web y Gestión):

<img src="docs/img/capturas/menu.png" alt="Menú de navegación">

<details>
<summary><b>Ver todas las secciones (19 capturas)</b></summary>

### Inicio

Score, hallazgos por severidad, dispositivos, cumplimiento y evolución del score a 30 días.

<img src="docs/img/capturas/dashboard.png" alt="Inicio">

### Red › Mi Red

Descubrimiento de dispositivos, auditoría SSH en paralelo y CVEs.

<img src="docs/img/capturas/network.png" alt="Red › Mi Red">

### Red › Subdominios

Enumeración por Certificate Transparency.

<img src="docs/img/capturas/subenum.png" alt="Red › Subdominios">

### Red › DNS Security

SPF, DMARC, DKIM, DNSSEC y CAA.

<img src="docs/img/capturas/dnssec.png" alt="Red › DNS Security">

### Red › Intel

IPs, dominios, hashes y emails en Shodan, VirusTotal, AbuseIPDB, GreyNoise, OTX y HIBP.

<img src="docs/img/capturas/intel.png" alt="Red › Intel">

### Sistema › Seguridad

Hardening del propio servidor con corrección automática.

<img src="docs/img/capturas/audit.png" alt="Sistema › Seguridad">

### Sistema › Malware

YARA, hashes, auditd, cron y webshells.

<img src="docs/img/capturas/malware.png" alt="Sistema › Malware">

### Sistema › Docker

Configuración de Docker y Kubernetes.

<img src="docs/img/capturas/docker.png" alt="Sistema › Docker">

### Sistema › Código

bandit, shellcheck, eslint y secretos.

<img src="docs/img/capturas/code.png" alt="Sistema › Código">

### Sistema › Servicios

nginx, apache, MySQL, PostgreSQL, Redis, MongoDB.

<img src="docs/img/capturas/services.png" alt="Sistema › Servicios">

### Web › TLS/SSL

Caducidad, autofirmados, protocolos y claves débiles.

<img src="docs/img/capturas/tls.png" alt="Web › TLS/SSL">

### Web › Cabeceras Web

HSTS, CSP, X-Frame-Options, cookies, fuga de información.

<img src="docs/img/capturas/webhdr.png" alt="Web › Cabeceras Web">

### Web › Exposición Web

.git, .env, copias de seguridad y métodos HTTP peligrosos.

<img src="docs/img/capturas/webexp.png" alt="Web › Exposición Web">

### Web › API / CORS

CORS, documentación de API expuesta, GraphQL.

<img src="docs/img/capturas/apisec.png" alt="Web › API / CORS">

### Web › Nuclei

Escáner por plantillas (CVEs y exposiciones).

<img src="docs/img/capturas/nuclei.png" alt="Web › Nuclei">

### Gestión › Historial

Todos los análisis con su score y comparación.

<img src="docs/img/capturas/history.png" alt="Gestión › Historial">

### Gestión › Monitor

Monitor eBPF/auditd en tiempo real y análisis de imágenes Docker.

<img src="docs/img/capturas/monitor.png" alt="Gestión › Monitor">

### Gestión › Informes

HTML, PDF, playbook Ansible, JSON para SIEM, compliance e importación de auditorías.

<img src="docs/img/capturas/reports.png" alt="Gestión › Informes">

### Gestión › Configuración

API keys, notificaciones, SIEM, ticketing, scheduler, usuarios, supresiones, 2FA, YARA, agentes, LDAP, cuarentena, SBOM, Ansible, mi cuenta (contraseña, sesiones y tokens de API), análisis programados, fixes remotos aplicados, registro de auditoría y organizaciones (multi-tenant).

<img src="docs/img/capturas/settings.png" alt="Gestión › Configuración">

</details>

---

## Requisitos

### Sistema
- **SO**: Linux x86_64 (Ubuntu 22.04/24.04, Debian 12/13, RHEL/Rocky/Alma 9+).
- **Python**: 3.11 o superior (solo para la instalación manual; la imagen Docker lo trae).
- **Privilegios**: varios análisis y las correcciones requieren `root` (detección de SO con nmap, `auditd`, monitor eBPF, fixes de hardening). La interfaz web puede ejecutarse sin root.
- **Red**: salida a internet para lo opcional (CVEs, plantillas de Nuclei, threat intelligence). Funciona en entornos aislados con cobertura reducida.

### Hardware

| | Mínimo | Recomendado |
|---|---|---|
| **CPU** | 2 vCPU | 4+ vCPU |
| **RAM** | 2 GB | 8 GB |
| **Disco** | 3 GB | 15+ GB SSD |

- Base (app + BD SQLite + logs): ~1 GB. **Plantillas de Nuclei**: ~1,5 GB adicionales.
- Lo que más consume es YARA sobre el sistema de ficheros y Nuclei con todas las plantillas. Para un homelab o PYME pequeña bastan 2 vCPU / 4 GB / 10 GB.

---

## Instalación

### Docker (un servidor, SQLite)

```bash
git clone https://github.com/jl-segurayuste/cyberhound-pro.git
cd cyberhound-pro
cp .env.example .env          # opcional: CH_PASSWORD, CH_HOST, API keys…
docker compose up -d
docker compose logs cyberhound | grep -i contraseña   # si no definiste CH_PASSWORD
```

Abre **https://localhost:8443** (certificado autofirmado: el navegador avisará). Usa la imagen que publica el CI (`ghcr.io/jl-segurayuste/cyberhound-pro:latest`); `docker compose build` construye una local con el código del repo.

- El contenedor usa la red del host (`network_mode: host`) para poder descubrir la LAN. Por defecto escucha solo en `127.0.0.1`; `CH_HOST=0.0.0.0` lo expone a la red.
- Todo lo persistente (configuración, BD, cuarentena, reglas YARA, certificado) vive en el volumen `/data`.
- `CH_PASSWORD` solo se usa al crear `/data/config.yaml` la primera vez. Después: `docker exec -it cyberhound cyberhound setup --config /data/config.yaml`.

### Producción (PostgreSQL + nginx + copias)

```bash
cp .env.example .env          # obligatorio: CH_PASSWORD y POSTGRES_PASSWORD; opcional CH_DOMAIN
docker compose -f docker-compose.production.yml up -d
```

| Servicio | Qué hace |
|---|---|
| `postgres` | PostgreSQL 16 en una red interna sin salida |
| `cyberhound` | La aplicación, con `CH_DB_URL` hacia PostgreSQL y solo accesible por nginx |
| `certs` | Genera un certificado autofirmado para nginx si no pones el tuyo en `docker/nginx/certs/` |
| `nginx` | TLS, HTTP→HTTPS y rate limit en `/login` y `/api/` (puertos `CH_HTTP_PORT`/`CH_HTTPS_PORT`) |
| `backup` | `pg_dump` al arrancar y cada 24 h; conserva las 30 últimas copias |

El rate limit de la aplicación ve la IP real del cliente (`CH_TRUSTED_PROXIES=nginx`).

### Manual (Linux, servicio systemd)

```bash
git clone https://github.com/jl-segurayuste/cyberhound-pro.git
cd cyberhound-pro
sudo bash install.sh                      # solo accesible desde este equipo
sudo bash install.sh --host 0.0.0.0       # accesible desde la red
sudo bash install.sh --postgres           # PostgreSQL local en lugar de SQLite
```

Instala en `/opt/cyberhound`, crea `/root/.cyberhound/config.yaml` con una contraseña aleatoria (la muestra una vez) y el servicio `cyberhound`. Probado en Ubuntu 24.04 y Debian 12. Para cambiar la contraseña: `sudo cyberhound setup --config /root/.cyberhound/config.yaml`.

---

## Usuarios, roles y 2FA

El administrador de `config.yaml` (`auth.username`) siempre es admin. Desde **Configuración › Usuarios** se crean más, con uno de estos roles:

| Rol | Puede |
|---|---|
| `viewer` | Ver todo (panel, historial, informes) |
| `operator` | Lo anterior + lanzar análisis y aplicar correcciones |
| `admin` | Lo anterior + configuración, usuarios y supresiones |

El servidor aplica los permisos en cada petición; la interfaz desactiva lo que el rol no permite. Un admin no puede quitarse su propio rol ni desactivarse. Cada usuario puede activar **2FA (TOTP)** con códigos de recuperación de un solo uso; para desactivarlo hace falta un código válido.

En **Configuración › Mi cuenta** cada usuario:

- **Cambia su contraseña**; sus demás sesiones se cierran.
- **Ve sus sesiones abiertas** (última actividad, IP, navegador) y cierra las que no reconozca. Las sesiones viven en la base de datos: al salir, cambiar la contraseña o desactivar al usuario dejan de valer al momento, aunque alguien haya copiado la cookie. Un admin puede cerrar todas las de otro usuario (`DELETE /api/users/{usuario}/sessions`).
- **Crea tokens de API** para scripts y CI (`Authorization: Bearer cht_…`), con rol (nunca por encima del suyo) y caducidad. Solo se muestran al crearlos (se guarda su hash) y no sirven para gestionar credenciales: contraseña, 2FA, sesiones ni otros tokens.

**Configuración › Auditoría** (admin) muestra el registro de la organización con filtros por acción, usuario, texto y fallos: inicios de sesión y sus fallos, cambios de usuarios, contraseñas, 2FA, tokens, fixes remotos, programaciones y configuración.

---

## Multi-tenant

Para un MSP o una instancia compartida: varias organizaciones **aisladas** en un solo CyberHound. Se activa con

```yaml
multi_tenant:
  enabled: true
```

y se gestionan en **Configuración › Organizaciones** (alta con su primer administrador, redes y dominios permitidos, nueva clave de agente, baja).

- **Datos separados**: cada organización tiene su propia base de datos (un fichero SQLite en `<dir de la BD>/tenants/<slug>.db` o un esquema `tenant_<slug>` en PostgreSQL): escaneos, hallazgos, activos, supresiones, usuarios, 2FA y agentes. La organización "Plataforma" es la BD de siempre, así que activarlo no mueve datos.
- **Login por organización**: el formulario pide la organización (o la toma del subdominio, `acme.cyberhound.ejemplo-demo.es`). La sesión queda ligada a ella y no se puede cambiar.
- **Superadmin**: el admin de `config.yaml` (organización vacía en el login) gestiona las organizaciones y puede ver cualquiera con el selector de la cabecera.
- **Ámbito de análisis**: cada organización solo puede analizar las redes, IPs y dominios que el superadmin le permite (un dominio incluye sus subdominios); sin ámbito no puede lanzar análisis activos. Se comprueba en cada análisis, en el descubrimiento de red, LDAP, los fixes remotos y los programados. Un dominio permitido que resuelve a una IP interna fuera del ámbito se rechaza, para que no sirva de puente a la red del servidor. Una organización tampoco puede usar claves SSH guardadas en el servidor.
- **Integraciones propias**: cada organización configura su correo, webhook, SIEM y Jira/ServiceNow, y recibe solo sus avisos. Sus destinos deben ser públicos o estar en su ámbito (se comprueba al guardar y antes de cada envío).
- **Reservado a la plataforma**: lo que actúa sobre el propio servidor o es configuración global (auditoría local, malware, Docker, servicios, código, fixes locales, cuarentena, YARA, SBOM, monitor, Ansible, scheduler de la plataforma, API keys de threat intel, modo agente). Una organización usa los análisis de red, web, DNS, intel, SSH remoto, LDAP, importación y sus propios análisis programados.
- **Agentes**: cada organización tiene su clave de agente (la ve su admin en Configuración › Agentes); sus informes solo llegan a ella.
- **Baja**: corta al momento sesiones y clave de agente y **archiva** sus datos (no se borran). Si se vuelve a crear el mismo identificador, empieza vacío.
- Los análisis de una organización salen desde el servidor de la plataforma. El ámbito decide qué puede pedir; el firewall del servidor sigue siendo la última barrera.

<p><img src="docs/img/capturas/organizaciones.png" alt="Configuración › Organizaciones" width="640"> <img src="docs/img/capturas/login-organizacion.png" alt="Login con organización" width="300"></p>

---

## Funcionalidades

### Panel de actividad en tiempo real

Cada hallazgo aparece conforme se detecta (WebSocket), con barra de progreso por análisis y contadores por severidad. El panel se abre solo ante un hallazgo crítico y la red se revisa cada 15 minutos en busca de dispositivos nuevos.

### Análisis en paralelo

Se pueden lanzar varios a la vez (red mientras corre Docker, malware en segundo plano…), cada uno con su progreso.

### Scoring contextual (0-100)

| Factor | Impacto |
|--------|---------|
| Categoría | `docker/escape` ×2.0, `ssh` y `firewall` ×1.5, `network` ×1.4, `updates` ×0.7… |
| Exposición | Expuesto a internet ×1.4, servidor web ×1.2 |
| Corrección automática disponible | ×0.75 (el riesgo es manejable) |
| Acumulación | Cada hallazgo repetido de la misma categoría pesa ×0.8 respecto al anterior |
| Bonus | +2 firewall bien, +2 SSH bien, +1 autenticación bien |

Grados: **A** (≥90) · **B** (≥75) · **C** (≥60) · **D** (≥40) · **F** (<40)

### Corrección automática y deshacer

Los hallazgos con ⚡ se corrigen con un clic, en local o en el host remoto donde se encontraron:

| Categoría | Ejemplos |
|-----------|----------|
| SSH | PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 4, permisos de las claves de host |
| Firewall | ufw / firewalld (antes de activar ufw abre SSH y el puerto de la web: no te deja fuera) |
| Kernel | `sysctl -w` + persistencia en `/etc/sysctl.d/99-cyberhound.conf` |
| Autenticación | pam_faillock, políticas de `login.defs`, bloquear cuentas sin contraseña |
| Sistema | core dumps, almacenamiento USB, Ctrl+Alt+Del, AppArmor, auditd, AIDE, NTP, umask, banners |
| Ficheros | world-writable, permisos de logs, `/etc/passwd` y `/etc/shadow`, sticky bit de `/tmp` |
| OpenSSH | actualización del paquete ante CVEs conocidos |

- **Deshacer** (fixes locales): cada fix guarda en un journal lo necesario para revertirlo (copia del fichero, permisos previos, estado del servicio o comando inverso) y el botón pasa a **↶ Deshacer**. Las instalaciones de paquetes se marcan como no reversibles: no se desinstala nada a ciegas.
- **Corrección remota**: el comando lo construye CyberHound a partir del hallazgo (nunca se ejecuta lo que devuelve el host auditado) y se lanza por SSH sin shell, con `sudo -n` si está disponible.
- **Deshacer** (fixes remotos): al aplicarlo, el host devuelve su estado anterior (la línea de `sshd_config`, el valor del sysctl, si el servicio estaba activo, los permisos del fichero, si ufw estaba apagado) y CyberHound guarda la acción inversa, validada porque viene del host. Se deshace desde el propio botón o desde **Configuración › Fixes remotos**, que lista los aplicados en la organización.

### Threat intelligence

Busca IPs, dominios, hashes (MD5/SHA1/SHA256) o emails en las fuentes con API key configurada, o analiza de golpe las IPs del último escaneo de red. Cada respuesta se traduce en hallazgos con severidad (p. ej. AbuseIPDB ≥75 % → crítico, CVEs en Shodan, detecciones de VirusTotal, pulsos de OTX, brechas de HIBP).

### Más

- **Cuarentena**: aparta un fichero sospechoso a `<datos>/quarantine/` ofuscado (XOR, no es cifrado: evita que se ejecute o que el antivirus lo vuelva a detectar) y permite restaurarlo verificando su SHA-256.
- **SBOM**: CycloneDX 1.4 y SPDX 2.3 de paquetes pip/npm/del sistema, con diferencias entre versiones.
- **Compliance**: cumplimiento de ENS, ISO 27001, PCI-DSS y CIS a partir de los hallazgos, en el informe PDF y con aviso si baja de un día a otro.
- **Informes**: HTML, PDF, JSON y playbook de Ansible con las correcciones.
- **Importación**: Nessus, OpenSCAP/XCCDF (RHEL STIG/CIS), CSV y JSON.
- **Supresiones**: patrones de falsos positivos con motivo y caducidad.
- **Análisis programados** (Configuración › Programados): red, cabeceras web, exposición, API/CORS, TLS, DNS, subdominios o Nuclei a la hora y los días elegidos, para la plataforma o para cada organización dentro de su ámbito. Se pueden lanzar a mano, pausar y borrar; los críticos avisan por las notificaciones de quien los programó. Aparte, el scheduler de la plataforma hace la auditoría diaria, el malware semanal y la red diaria del propio servidor.
- **Explicación con IA**: un LLM local (Ollama) explica un hallazgo en lenguaje llano (opcional).

---

## Arquitectura

```
cyberhound/
├── __init__.py              # __version__ (única fuente de la versión)
├── __main__.py              # CLI: web / setup / version
├── api/
│   ├── server.py            # aiohttp: estado, registro de rutas y arranque
│   ├── common.py            # middlewares (CSP, tenant, RBAC, métricas) y permisos por ruta
│   ├── handlers/            # endpoints por área: scans, fixes, data, accounts, schedules, config, platform
│   └── routes/intel_routes.py
├── core/
│   ├── auth.py              # login, JWT, 2FA, rate limit del login
│   ├── security.py          # validación de entradas, IP real tras proxies, CSRF/origen, TLS
│   ├── passwords.py         # PBKDF2-HMAC-SHA256
│   ├── totp.py              # 2FA TOTP (secreto cifrado en la BD) y códigos de recuperación
│   ├── config.py · paths.py # YAML + variables de entorno · directorio de datos (CH_DATA_DIR)
│   ├── database.py          # SQLite (WAL)
│   ├── database_pg.py       # PostgreSQL (asyncpg), misma interfaz
│   ├── multitenancy.py      # tenants, BD por tenant y enrutado por petición
│   ├── scope.py             # ámbito de análisis de cada organización
│   ├── integrations.py      # notificaciones/SIEM/ticketing por organización, con control de destinos
│   ├── accounts_db.py       # sesiones, tokens de API y auditoría (SQLite y PostgreSQL)
│   ├── schedules.py · remote_fixes.py   # análisis programados · fixes remotos que se pueden deshacer
│   ├── scoring.py · scheduler.py · notifications.py · siem.py · ticketing.py
│   ├── agent.py · rollback.py · quarantine.py · ebpf_monitor.py · llm.py
│   ├── ansible_integration.py · openapi.py · executor.py · logging.py · models.py
├── scanners/                # hardening, network, ssh_audit, malware, docker_scan, kubernetes_scan,
│                            # docker_image_scan, runtime_scan, code, secrets, services_audit, tls_scan,
│                            # web_headers, web_exposure, api_security, dns_security, subdomain_enum,
│                            # nuclei_scan, intel, ldap_audit, compliance, sbom, audit_import,
│                            # reports, pdf_report
└── ui/static/               # SPA: index.html, js/ (por áreas, en orden de carga), style.css (sin JS en línea), Swagger
```

---

## Checks de hardening (31 checks)

⚡ = corrección automática.

### SSH (`/etc/ssh/sshd_config`)
| ID | Verifica | Fix |
|----|---------|-----|
| `ssh_PermitRootLogin` · `ssh_PasswordAuthentication` · `ssh_PermitEmptyPasswords` · `ssh_X11Forwarding` | Valores inseguros | ⚡ |
| `ssh_MaxAuthTries` | MaxAuthTries > 4 | ⚡ |
| `ssh_protocol1` | Protocol 1 activo | ⚡ |
| `ssh_hostkey_perm_*` | Claves de host con permisos distintos de 600 | ⚡ |
| `openssh_cve_*` | Versión de OpenSSH con CVEs conocidos | ⚡ actualizar |

### Firewall y red
| ID | Verifica | Fix |
|----|---------|-----|
| `fw_ufw_inactive` · `fw_firewalld_inactive` | Firewall instalado pero inactivo | ⚡ |
| `fw_none` | Sin firewall | manual |
| `kernel_*` | 10 parámetros: ip_forward, send_redirects, accept_source_route, ASLR, SYN cookies, log_martians, rp_filter, dmesg_restrict, perf_event_paranoid, IPv6 | ⚡ |
| `svc_listen_all_*` | Bases de datos/cachés escuchando en 0.0.0.0 | manual |
| `ipv6_enabled_unused` | IPv6 activo sin uso | manual |

### Autenticación y cuentas
| ID | Verifica | Fix |
|----|---------|-----|
| `no_pam_faillock` | Sin bloqueo por intentos fallidos | ⚡ |
| `login_defs_*` | PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE, LOGIN_RETRIES | ⚡ |
| `empty_password_*` | Cuentas sin contraseña | ⚡ bloquear |
| `duplicate_uid0_*` | UID 0 en una cuenta que no es root | manual |
| `sudoers_nopasswd_*` | NOPASSWD en sudoers | manual |
| `passwd_perm_*` | Permisos excesivos en `/etc/passwd` o `/etc/shadow` | ⚡ |
| `grub_no_password` | GRUB sin contraseña | manual |

### Sistema
| ID | Verifica | Fix |
|----|---------|-----|
| `svc_*` | Servicios inseguros activos (telnet, rsh, rlogin, finger, talk, tftp, xinetd, nis) | ⚡ desactivar |
| `no_auditd` · `auditd_inactive` | auditd ausente o parado | ⚡ |
| `no_aide` · `aide_db_missing` | Sin AIDE o sin su base de datos | ⚡ |
| `apparmor_inactive` | AppArmor inactivo | ⚡ |
| `core_dumps_enabled` · `usb_storage_enabled` · `ctrlaltdel_enabled` | Core dumps, USB, Ctrl+Alt+Del | ⚡ |
| `no_unattended_upgrades` | Sin actualizaciones automáticas | ⚡ |
| `no_ntp` | Sin NTP/chrony | ⚡ |
| `umask_insecure_*` | umask permisivo | ⚡ |
| `no_banner_*` | Banners de login vacíos | ⚡ |
| `cron_unrestricted` · `cron_no_restriction` · `at_no_restriction` | cron/at sin restringir | manual |
| `log_perm_*` | Logs legibles por todos | ⚡ |
| `ww_*` | Ficheros world-writable | ⚡ |
| `tmp_*` | `/tmp` y `/var/tmp` sin noexec/nosuid | manual |
| `tmp_no_sticky_bit` | `/tmp` sin sticky bit | ⚡ |

---

## Checks Docker y Kubernetes

### Docker (7 checks)
| Check | Severidad | Descripción |
|-------|-----------|-------------|
| Contenedores como root | High | Sin `User` definido |
| Privilegiados / capacidades | Critical | `--privileged` o capacidades peligrosas |
| `docker.sock` montado | Critical | Control total del host desde el contenedor |
| Secretos en variables de entorno | High | Credenciales en `Env` |
| Montajes peligrosos | Critical | `/etc`, `/proc`, `/`… del host |
| Imágenes antiguas | Medium | Más de 90 días sin actualizar |
| CVEs en imágenes | Critical/High | Con Trivy |

### Kubernetes (11 checks vía kubectl)
Pods como root, contenedores privilegiados, ClusterRoles con `*`, token de ServiceAccount montado, namespaces sin NetworkPolicy, contenedores sin límites, imágenes `:latest`, secretos en variables, hostPath peligrosos, versión de Kubernetes con CVEs y namespaces sin Pod Security Admission.

---

## API REST y WebSocket

La referencia completa está en **`/api/docs`** (Swagger UI, servida por la propia instancia) y en `/api/openapi.json`: todas las rutas están documentadas (un test lo comprueba). Autenticación: la cookie de sesión del navegador o `Authorization: Bearer <token>` (un token de API `cht_…` de Configuración › Mi cuenta, o el JWT de la sesión); los agentes usan `Authorization: AgentKey <clave>`.

### Endpoints principales

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/login` | Inicio de sesión (formulario con CSRF; luego código 2FA si está activo) |
| `GET` | `/health` | Healthcheck (sin autenticación) |
| `GET` | `/api/me` | Usuario, rol, permisos y organización de la sesión |
| `GET` | `/api/dashboard` | Datos del panel |
| `GET` | `/api/history` · `/api/history/{scan_id}` · `/api/history/{scan_id}/compare` | Historial, detalle y comparación |
| `GET` | `/api/score/trend` · `/api/score/detail` | Tendencia y desglose del score |
| `GET` · `POST` | `/api/assets` · `/api/assets/{ip}/authorize` | Inventario de dispositivos |
| `GET` · `POST` · `DELETE` | `/api/suppressions` | Falsos positivos |
| `GET` · `POST` · `PATCH` · `DELETE` | `/api/users` · `/api/users/{usuario}/sessions` | Usuarios y cerrar todas sus sesiones |
| `POST` | `/api/me/password` | Cambiar la propia contraseña |
| `GET` · `POST` · `DELETE` | `/api/sessions` · `/api/sessions/revoke-others` · `/api/sessions/{id}` | Mis sesiones |
| `GET` · `POST` · `DELETE` | `/api/tokens` · `/api/tokens/{id}` | Tokens de API |
| `GET` | `/api/audit` | Registro de auditoría (`action`, `user`, `q`, `failures`, `limit`) |
| `POST` | `/api/fix/local` · `/api/fix/remote` · `/api/rollback/local` | Corregir y deshacer (local) |
| `GET` · `POST` | `/api/fix/remote/history` · `/api/fix/remote/undo` | Fixes remotos aplicados y deshacerlos |
| `GET` · `POST` · `PATCH` · `DELETE` | `/api/schedules` · `/api/schedules/{id}` · `/api/schedules/{id}/run` | Análisis programados |
| `POST` | `/api/report/{html\|ansible\|json}` · `/api/report/pdf` | Informes |
| `POST` · `GET` | `/api/intel/scan` · `/api/intel/lookup` | Threat intelligence |
| `GET` · `POST` | `/api/config/{keys\|notifications\|siem\|ticketing\|agent}` | Configuración |
| `GET` · `POST` · `PATCH` · `DELETE` | `/api/tenants` | Organizaciones y su ámbito (`allowed_targets`) (multi-tenant, superadmin) |
| `GET` | `/metrics` | Métricas Prometheus (sin sesión solo desde el propio host) |

### Tareas WebSocket (`/ws`)

```json
{ "task": "audit" }
{ "task": "malware", "skip": ["hash"], "web_roots": ["/var/www"] }
{ "task": "network", "networks": "192.168.1.0/24", "ssh_audit": true }
{ "task": "ssh", "hosts": "192.168.1.10,192.168.1.20", "ssh_user": "root" }
{ "task": "docker", "scan_images_cve": true, "scan_k8s": true }
{ "task": "code", "path": "/var/www/html" }
{ "task": "services" }
{ "task": "intel", "target": "203.0.113.7", "modules": ["shodan", "virustotal"] }
{ "task": "tls", "targets": ["www.ejemplo-demo.es"] }
{ "task": "web_headers", "urls": ["https://www.ejemplo-demo.es"] }
{ "task": "web_exposure", "urls": ["https://www.ejemplo-demo.es"] }
{ "task": "api_security", "urls": ["https://api.ejemplo-demo.es"] }
{ "task": "nuclei", "urls": ["https://www.ejemplo-demo.es"], "severities": ["high", "critical"] }
{ "task": "dns", "domains": ["ejemplo-demo.es"] }
{ "task": "subdomain_enum", "domains": ["ejemplo-demo.es"] }
```

---

## Seguridad implementada

### Autenticación y sesión
- Contraseñas con **PBKDF2-HMAC-SHA256** (600 000 iteraciones, sal aleatoria); los hashes SHA-256 antiguos se migran al iniciar sesión.
- **JWT HS256** con secreto persistente en `config.yaml` (0600), en cookie `HttpOnly` + `SameSite=Strict` + `Secure` con HTTPS.
- **2FA TOTP** con anti-repetición; el secreto se guarda **cifrado** (Fernet, clave derivada del secreto de la instancia) y los códigos de recuperación como hash. El token intermedio "falta el código" nunca vale como sesión.
- **Sesiones revocables**: cada JWT lleva el id de una sesión guardada en la BD, que se comprueba en cada petición; salir, cambiar la contraseña o desactivar al usuario la invalidan al momento.
- **Tokens de API** con hash SHA-256 en la BD, rol tope y caducidad; con un token no se gestionan credenciales.
- **Roles** (viewer/operator/admin) aplicados por middleware en cada petición; usuarios desactivados pierden la sesión al instante.
- **Rate limiting del login**: 5 intentos en 15 min → bloqueo de 15 min, luego 1 h y 24 h. Detrás de un proxy inverso (`server.trusted_proxies`) usa la IP real del cliente; sin él, ignora `X-Forwarded-For` (no se puede falsear). Localhost nunca se bloquea.

### Peticiones
- **CSRF**: doble envío (cookie + campo) en el formulario de login; las escrituras en `/api/*` que un navegador marque como de otro origen (`Sec-Fetch-Site` / `Origin`, también otro subdominio) se rechazan.
- **CSP con nonce** por petición y `script-src-attr 'none'`: la interfaz no usa JS en línea (eventos delegados con `data-on-*`), así que ni un atributo inyectado ejecuta código.
- `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`.
- Entradas validadas: lista blanca de tareas WS, IPs con `ipaddress`, redes de como mucho /16 (máx. 5 por petición), máx. 50 hosts por análisis, rutas sin traversal, indicadores de intel validados antes de usarlos en URLs.
- Informes HTML con todo escapado: los títulos de hallazgos pueden venir de webs o agentes de terceros.

### Ejecución
- Ningún `shell=True` ni `os.system`. La corrección remota no ejecuta texto que venga del host auditado: construye la acción desde el id del hallazgo, la pasa como dato y el script remoto va por stdin (nada en `/tmp` que otro usuario pueda sustituir antes del `sudo`).
- Un hallazgo de otro host no se puede corregir en local por error, y el fix remoto se aplica en el host del hallazgo, no en el que diga la petición.

### TLS
- Certificado RSA 4096 autofirmado en el primer arranque (o el tuyo con `server.tls_cert`/`tls_key`), TLS 1.2+ y cifrados modernos.

### Auditoría
`<log_dir>/security_audit.log`: logins (con la IP real), fallos de permisos, fixes aplicados y análisis lanzados. Además, cada organización tiene su registro en la BD (`audit_events`), consultable desde **Configuración › Auditoría** o `/api/audit`.

---

## Integraciones

| Integración | Detalle |
|---|---|
| **Wazuh** | UDP al agente (1514) o API del manager; decoders y reglas en [`wazuh/`](wazuh/) |
| **Elasticsearch** | Índice configurable (`cyberhound-findings`), API key o usuario/contraseña |
| **Splunk** | HTTP Event Collector, índice y sourcetype configurables |
| **Jira / ServiceNow** | Un ticket por hallazgo **nuevo** por encima del umbral (sin duplicar a diario) |
| **Por organización** | En multi-tenant, correo, webhook, SIEM y ticketing son de cada organización |
| **Email / webhooks** | SMTP con TLS; Slack, Teams o Discord por webhook |
| **AWX / Tower** | Lanza playbooks de remediación |
| **Agentes** | Otros servidores con CyberHound en modo `agent` envían sus hallazgos a un `manager` |
| **Prometheus** | `/metrics` |
| **Ollama** | LLM local para explicar hallazgos (`OLLAMA_URL`, `CYBERHOUND_LLM_MODEL`) |

---

## Configuración

`config.yaml` (por defecto en `~/.cyberhound/`, en Docker `/data/config.yaml`). Las variables de entorno mandan sobre el fichero. Lo que se cambia desde la interfaz se guarda en ese mismo fichero.

```yaml
auth:
  mode: jwt                 # jwt | basic | none (none: solo desde localhost)
  username: admin
  password_hash: "…"        # lo escribe 'cyberhound setup'
  secret: "…"               # se genera solo
  token_ttl_hours: 8

server:
  host: 127.0.0.1           # seguro por defecto; 0.0.0.0 para exponer en la red
  port: 8443
  tls_cert: null            # null = autofirmado
  tls_key: null
  trusted_proxies: []       # IP, CIDR o nombre del proxy inverso (p. ej. ["10.0.0.5"])

db_path: ~/.cyberhound/cyberhound.db
db_url: ""                  # postgresql://usuario:clave@host:5432/bd (vacío = SQLite)

multi_tenant:
  enabled: false

scan:
  ssh_key_path: ~/.ssh/id_ed25519
  ssh_default_user: root
  ssh_concurrency: 5

scheduler:
  enabled: true
  audit_hour: 2             # auditoría diaria 02:00
  malware_day: 0            # malware los lunes (0 = lunes) a las 03:00
  malware_hour: 3
  network_hour: 4           # red diaria 04:00

notifications:
  email_enabled: false
  smtp_host: smtp.gmail.com
  min_level: warning        # info | warning | critical

siem:
  wazuh_enabled: false
  elk_enabled: false
  splunk_enabled: false
  min_severity: medium
```

Para cambiar la contraseña o el puerto: `cyberhound setup` (asistente) o `printf '%s\n' "$CLAVE" | cyberhound setup --password-stdin`.

### Variables de entorno

| Variable | Descripción |
|----------|-------------|
| `CH_DATA_DIR` | Directorio de datos persistentes (config, BD, cuarentena, reglas YARA, certificado). Docker: `/data` |
| `CH_DB_URL` | URL de PostgreSQL (si no, SQLite) |
| `CH_HOST` · `CH_PORT` | Interfaz y puerto (Docker) |
| `CH_USERNAME` · `CH_PASSWORD` | Usuario y contraseña del primer arranque (Docker; vacía = se genera) |
| `CH_SECRET` | Secreto de las sesiones JWT |
| `CH_TRUSTED_PROXIES` | Proxies inversos de confianza (IP, CIDR o nombre, separados por comas) |
| `CH_TLS_DIR` | Dónde guardar el certificado autofirmado |
| `SHODAN_API_KEY` · `VT_API_KEY` · `ABUSEIPDB_KEY` · `GREYNOISE_KEY` · `OTX_KEY` · `HIBP_API_KEY` | Threat intelligence |
| `CH_SMTP_PASSWORD` · `CH_WEBHOOK_URL` | Notificaciones |
| `CH_WAZUH_URL` · `CH_WAZUH_USER` · `CH_WAZUH_PASS` | API de Wazuh |
| `CH_ELK_API_KEY` · `CH_ELK_PASS` · `CH_SPLUNK_TOKEN` | Elasticsearch y Splunk |
| `CH_JIRA_TOKEN` · `CH_SERVICENOW_PASS` | Ticketing |
| `CH_AGENT_KEY` | Clave de los agentes |
| `CH_SSH_KEY` | Clave SSH privada (contenido) para el contenedor |
| `OLLAMA_URL` · `CYBERHOUND_LLM_MODEL` | LLM local |
| `POSTGRES_PASSWORD` · `CH_DOMAIN` · `CH_HTTP_PORT` · `CH_HTTPS_PORT` | Compose de producción |

Los secretos que llegan por entorno no se copian al fichero.

---

## Tests

**729 tests** en 53 ficheros (`tests/test_*.py`), que el CI ejecuta en Python 3.11 y 3.12 y otra vez contra PostgreSQL 16.

```bash
pip install -e ".[test]"
pytest tests/                                              # SQLite
CH_DB_URL=postgresql://usuario:clave@host:5432/bd pytest tests/   # la misma suite contra PostgreSQL
```

Además de las pruebas unitarias hay tests de extremo a extremo sobre la aplicación real (login con 2FA, roles, aislamiento entre organizaciones, correcciones, threat intel) y de coherencia: toda ruta está en OpenAPI, los permisos de la interfaz coinciden con los del servidor y la versión sale de un único sitio.

### Batería E2E en navegador

[`scripts/e2e/`](scripts/e2e/) levanta instancias de demo con datos ficticios y las recorre con Chromium: los 19 paneles en escritorio, tablet y móvil (scroll y desbordamiento), cada botón y control, los roles, el multi-tenant y la API con análisis reales contra objetivos controlados. Ver su [README](scripts/e2e/README.md).

---

## Herramientas del sistema recomendadas

| Herramienta | Para qué | Instalación |
|-------------|---------|-------------|
| `nmap` | Red, detección de SO, CVEs | `sudo apt install nmap` |
| `arp-scan` | Descubrimiento LAN | `sudo apt install arp-scan` |
| `nuclei` | Plantillas (CVEs, exposiciones) | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) + `nuclei -update-templates` |
| `trivy` | CVEs en imágenes Docker | [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy/) |
| `kubectl` | Kubernetes | [kubernetes.io/docs](https://kubernetes.io/docs/tasks/tools/) |
| `gitleaks` · `semgrep` | Secretos y análisis multilenguaje | [gitleaks](https://github.com/gitleaks/gitleaks/releases) · `pip install semgrep` |
| `shellcheck` · `bandit` | Bash y Python | `sudo apt install shellcheck` · `pip install bandit` |
| `auditd` · `bpftrace` | Monitor en tiempo real | `sudo apt install auditd bpftrace` |

---

## Roadmap

### ✅ Implementado (v6.5)

Los cambios de cada versión están en [CHANGELOG.md](CHANGELOG.md).

Todo lo descrito arriba: hardening con fixes y deshacer, red, SSH remoto, malware y cuarentena, Docker/K8s/imágenes/runtime, código y secretos, web (TLS, cabeceras, exposición, API/CORS, Nuclei), DNS y subdominios, threat intelligence, scoring, compliance, SBOM, LDAP/AD (6 checks: AS-REP roasting, admins del dominio, cuentas sin caducidad…), monitor, 2FA, roles, sesiones revocables, tokens de API, auditoría, multi-tenant con ámbito e integraciones por organización, análisis programados, deshacer fixes remotos, agentes, SIEM, ticketing, AWX, OpenAPI, SQLite y PostgreSQL, interfaz responsive (escritorio, tablet y móvil).

### 🔜 Ideas para futuras versiones

- **ML scoring**: modelo entrenado con el histórico para priorizar mejor.
- **App móvil nativa** con notificaciones push reales.
- **Marketplace de reglas YARA** con actualización automática.
- **Exportación a Elastic Security**: timeline de incidentes y reglas de correlación.

---

## Licencia

AGPL-3.0 — ver [LICENSE](LICENSE). Todo el código y todas las funciones están bajo esa licencia, sin ediciones ni limitaciones de pago. Copyright © 2026 José Luis Segura Yuste.

*Desarrollado para hacer la ciberseguridad accesible a las PYMEs*
