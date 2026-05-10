# 🐾 CyberHound Pro

> **Plataforma de auditoría y seguridad para PYMEs**  
> Analiza toda tu red, detecta vulnerabilidades y las corrige — sin agentes, sin configuración compleja.

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

---

## 📋 Índice

- [¿Qué es CyberHound?](#qué-es-cyberhound)
- [Funcionalidades](#funcionalidades)
- [Arquitectura](#arquitectura)
- [Instalación](#instalación)
- [Uso](#uso)
- [Módulos en detalle](#módulos-en-detalle)
- [API REST y WebSocket](#api-rest-y-websocket)
- [Seguridad](#seguridad)
- [Configuración](#configuración)
- [Contribuir](#contribuir)
- [Roadmap](#roadmap)

---

## ¿Qué es CyberHound?

CyberHound Pro es una herramienta de auditoría de seguridad diseñada para **pequeñas y medianas empresas** que no tienen un equipo de ciberseguridad dedicado. Proporciona:

- **Descubrimiento automático** de todos los dispositivos conectados a la red
- **Auditoría de seguridad** con más de 70 checks configurables
- **Detección de malware** mediante YARA, análisis de hashes y comportamiento
- **Corrección automática** de vulnerabilidades con un clic
- **Análisis remoto** de múltiples hosts simultáneamente vía SSH seguro
- **Interfaz web** intuitiva orientada a usuarios no técnicos

---

## Funcionalidades

### 🔍 Hardening Audit

Analiza la configuración de seguridad del sistema con más de 70 checks:

| Categoría | Checks |
|-----------|--------|
| **SSH** | PermitRootLogin, PasswordAuthentication, MaxAuthTries, X11Forwarding, Protocol |
| **Firewall** | UFW/firewalld activo |
| **Kernel** | ASLR, SYN cookies, IP forwarding, ICMP redirects, log martians |
| **Autenticación** | pam_faillock, política de contraseñas (login.defs) |
| **Servicios** | Telnet, rsh, nis, finger, tftp, xinetd activos |
| **Filesystem** | Ficheros world-writable, permisos de logs |
| **Integridad** | AIDE, auditd |
| **Sistema** | Core dumps, USB storage, Ctrl+Alt+Del, AppArmor |
| **Actualizaciones** | unattended-upgrades |

Cada hallazgo incluye severidad, descripción en lenguaje claro, remediación exacta y botón de corrección automática.

### 📡 Network Scan

1. **Descubrimiento** mediante nmap, arp-scan y caché ARP
2. **Análisis profundo**: puertos, servicios, versiones, OS detection
3. **CVEs** mediante scripts NSE de nmap
4. **Clasificación de riesgo** automática por dispositivo
5. **SSH audit** automático en hosts con SSH abierto

### 🖥️ SSH Audit

- Usa **asyncssh** — credenciales nunca en `ps aux`
- Copia el script vía SFTP (no SCP externo)
- Concurrencia configurable (5 hosts por defecto)
- Corrección remota con whitelist de comandos seguros

### 🦠 Malware Scan

| Módulo | Descripción |
|--------|-------------|
| **YARA** | Reglas integradas + externas. Detecta webshells, reverse shells, ELF en /tmp |
| **Hash Scanner** | SHA-256 de binarios contra MalwareBazaar (sin key) y VirusTotal |
| **Auditd Monitor** | Analiza audit.log buscando 12 patrones de comportamiento malicioso |
| **Cron Analyzer** | Detecta cron/systemd sospechosos: pipe a shell, scripts en /tmp, IPs hardcodeadas |
| **Webshell Scanner** | Análisis heurístico de PHP/JSP/ASP con puntuación ponderada |

### 📝 Code Audit + Secretos

- **bandit** (Python), **shellcheck** (Bash), **eslint** (JS/TS)
- Secretos: **gitleaks** → **trufflehog** → **semgrep** → regex (fallback)
- Detecta `.env` expuestos y claves privadas en el repo

### 🌐 Intel Scan

Shodan · VirusTotal · AbuseIPDB · GreyNoise · AlienVault OTX · HaveIBeenPwned

### 🔧 Remediación automática

Todos los hallazgos con fix posible tienen botón ⚡, tanto para el sistema local como para hosts remotos vía SSH.

### 📊 Exportación

HTML · Ansible Playbook · JSON (SIEM) · Log de sesión

---

## Arquitectura

```
cyberhound/
├── __main__.py          # Punto de entrada CLI
├── pyproject.toml       # Metadatos y dependencias
│
├── core/                # Módulos base
│   ├── models.py        # Finding, HostResult, ScanReport
│   ├── config.py        # Configuración tipada YAML + env vars
│   ├── auth.py          # JWT/Basic Auth + middleware aiohttp
│   ├── logging.py       # Logging estructurado JSON + journald
│   └── executor.py      # Comandos async + ThreadPoolExecutor
│
├── scanners/            # Módulos de análisis
│   ├── hardening.py     # Checks de hardening + HardeningFixer
│   ├── malware.py       # YARA + hashes + auditd + cron + webshells
│   ├── network.py       # Descubrimiento + nmap XML parsing
│   ├── ssh_audit.py     # Audit remoto con asyncssh
│   ├── code.py          # bandit + shellcheck + eslint
│   ├── secrets.py       # gitleaks → trufflehog → semgrep → regex
│   ├── intel.py         # APIs externas
│   └── reports.py       # HTML + Ansible
│
├── api/
│   └── server.py        # aiohttp + WebSocket + auth middleware
│
└── ui/static/
    ├── index.html       # SPA
    ├── style.css        # Dark theme
    └── app.js           # WebSocket, dashboard, filtros
```

### Flujo de comunicación

```
Browser ──WebSocket──► api/server.py ──► scanners/*
                                    ◄── findings (streaming en tiempo real)
        ──REST POST──► /api/fix/*   ──► HardeningFixer / RemoteAuditor
        ──REST POST──► /api/report  ──► ReportGenerator
```

---

## Instalación

### Docker (recomendado)

```bash
git clone https://github.com/qjossyx/cyberhound-pro.git
cd cyberhound-pro
cp .env.example .env
nano .env          # Cambiar CH_PASSWORD
docker compose up -d
# Abrir http://localhost:8443
```

**Sin docker-compose:**
```bash
docker run -d \
  --name cyberhound \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e CH_PASSWORD=mi_contraseña_segura \
  -v cyberhound-data:/data \
  -v ~/.ssh:/root/.ssh:ro \
  ghcr.io/qjossyx/cyberhound-pro:latest
```

**Variables de entorno Docker:**

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `CH_USERNAME` | `admin` | Usuario de acceso |
| `CH_PASSWORD` | `cyberhound` | Contraseña (cambiar siempre) |
| `CH_PORT` | `8443` | Puerto de escucha |
| `SHODAN_API_KEY` | — | API key de Shodan |
| `VT_API_KEY` | — | API key de VirusTotal |
| `ABUSEIPDB_KEY` | — | API key de AbuseIPDB |

### Instalación manual

```bash
git clone https://github.com/qjossyx/cyberhound-pro.git
cd cyberhound-pro
chmod +x install.sh && ./install.sh
sudo cyberhound web --port 8443
```

---

## Uso

### Interfaz web

| Sección | Descripción |
|---------|-------------|
| 🏠 **Inicio** | Dashboard: puntuación de seguridad (0-100), contadores, problemas críticos |
| 📡 **Mi Red** | Escaneo de red + audit SSH en todos los dispositivos |
| 🔍 **Seguridad** | Hardening audit del sistema local |
| 🦠 **Malware** | Escaneo de malware con todos los módulos |
| 📝 **Código** | Análisis estático de proyectos |
| 📊 **Informes** | Exportar en HTML, Ansible, JSON |
| ⚙️ **Config** | API keys, SSH, contraseña |

### CLI

```bash
cyberhound version          # Ver versión
sudo cyberhound setup       # Configuración inicial / cambiar contraseña
sudo cyberhound web --port 8443          # Lanzar servidor
sudo cyberhound web --port 8443 &        # En segundo plano
```

### Cambiar contraseña

```bash
sudo cyberhound setup
```

O manualmente:
```bash
HASH=$(python3 -c "import hashlib; print(hashlib.sha256(b'nueva_pass').hexdigest())")
sudo sed -i "s/password_hash:.*/password_hash: $HASH/" /root/.cyberhound/config.yaml
```

---

## Módulos en detalle

## Checks de Hardening — Detalle completo

Cuando ejecutas **🔍 Análisis de seguridad**, CyberHound realiza los siguientes checks en el servidor local. Cada check está implementado en `cyberhound/scanners/hardening.py`.

---

### 🔐 SSH (`/etc/ssh/sshd_config`)

| ID | Parámetro verificado | Valor inseguro | Severidad | Fix automático |
|----|---------------------|----------------|-----------|----------------|
| `ssh_PermitRootLogin` | PermitRootLogin | yes | High | ✅ `PermitRootLogin no` |
| `ssh_PasswordAuthentication` | PasswordAuthentication | yes | High | ✅ `PasswordAuthentication no` |
| `ssh_PermitEmptyPasswords` | PermitEmptyPasswords | yes | Critical | ✅ `PermitEmptyPasswords no` |
| `ssh_X11Forwarding` | X11Forwarding | yes | Medium | ✅ `X11Forwarding no` |
| `ssh_MaxAuthTries` | MaxAuthTries | > 4 | Medium | ✅ `MaxAuthTries 4` |
| `ssh_protocol1` | Protocol | 1 | Critical | ✅ Eliminar `Protocol 1` |

**Cómo funciona:** Lee `/etc/ssh/sshd_config` con `read_file_async()` y busca con regex línea por línea. Tras aplicar el fix, ejecuta `systemctl reload sshd`.

---

### 🔥 Firewall

| ID | Qué verifica | Severidad | Fix automático |
|----|-------------|-----------|----------------|
| `fw_ufw_inactive` | UFW instalado pero inactivo (`ufw status` → inactive) | Critical | ✅ `ufw --force enable` |
| `fw_firewalld_inactive` | firewalld instalado pero inactivo | Critical | ✅ `systemctl enable --now firewalld` |
| `fw_none` | Ni UFW ni firewalld detectados | Critical | ❌ Manual |

---

### ⚙️ Parámetros del Kernel (`/proc/sys/`)

Lee directamente desde `/proc/sys/` sin ejecutar `sysctl`. Tras el fix, persiste en `/etc/sysctl.d/99-cyberhound.conf`.

| ID | Parámetro | Valor esperado | Severidad | Descripción |
|----|-----------|---------------|-----------|-------------|
| `kernel_net_ipv4_ip_forward` | net.ipv4.ip_forward | 0 | High | Previene que el servidor actúe como router no intencionado |
| `kernel_net_ipv4_tcp_syncookies` | net.ipv4.tcp_syncookies | 1 | High | Protección contra ataques SYN flood |
| `kernel_kernel_randomize_va_space` | kernel.randomize_va_space | 2 | High | ASLR completo activado (mitigación de exploits) |
| `kernel_net_ipv4_conf_all_accept_source_route` | net.ipv4.conf.all.accept_source_route | 0 | High | Deshabilita enrutamiento por origen (IP spoofing) |
| `kernel_net_ipv4_conf_all_send_redirects` | net.ipv4.conf.all.send_redirects | 0 | High | Deshabilita envío de ICMP redirects |
| `kernel_net_ipv4_conf_all_log_martians` | net.ipv4.conf.all.log_martians | 1 | Medium | Loguea paquetes con IPs imposibles |
| `kernel_net_ipv4_conf_all_rp_filter` | net.ipv4.conf.all.rp_filter | 1 | Medium | Filtro de ruta inversa anti-spoofing |
| `kernel_kernel_dmesg_restrict` | kernel.dmesg_restrict | 1 | Medium | Restringe acceso a dmesg sin privilegios |
| `kernel_kernel_perf_event_paranoid` | kernel.perf_event_paranoid | 2 | Medium | Restringe acceso a eventos de rendimiento |
| `kernel_net_ipv6_conf_all_disable_ipv6` | net.ipv6.conf.all.disable_ipv6 | 1 | Info | IPv6 activo (revisar si se usa) |

---

### 🔒 Autenticación y contraseñas

| ID | Qué verifica | Archivo | Severidad | Fix automático |
|----|-------------|---------|-----------|----------------|
| `no_pam_faillock` | pam_faillock configurado en PAM | `/etc/pam.d/common-auth` | High | ✅ Inserta `auth required pam_faillock.so deny=5 unlock_time=600` |
| `login_defs_PASS_MAX_DAYS` | Caducidad máxima contraseñas ≤ 90 días | `/etc/login.defs` | Medium | ✅ `PASS_MAX_DAYS 90` |
| `login_defs_PASS_MIN_DAYS` | Días mínimos antes de cambiar ≥ 1 | `/etc/login.defs` | Low | ✅ `PASS_MIN_DAYS 1` |
| `login_defs_PASS_WARN_AGE` | Aviso de expiración ≥ 7 días | `/etc/login.defs` | Low | ✅ `PASS_WARN_AGE 7` |
| `login_defs_LOGIN_RETRIES` | Intentos de login ≤ 5 | `/etc/login.defs` | Medium | ✅ `LOGIN_RETRIES 5` |

**pam_faillock:** Bloquea la cuenta tras 5 intentos fallidos durante 600 segundos. También añade `account required pam_faillock.so` en `common-account`.

---

### 📁 Sistema de ficheros

| ID | Qué verifica | Severidad | Fix automático |
|----|-------------|-----------|----------------|
| `ww_<ruta>` | Fichero world-writable en `/etc`, `/usr/bin`, `/sbin`, etc. | High | ✅ `chmod o-w <ruta>` |
| `log_perm_<nombre>` | Fichero de log en `/var/log` legible por todos | Low | ✅ `chmod o-r <ruta>` |

**World-writable:** Escanea `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`. Genera un Finding individual por fichero (máx. configurable con `scan.max_ww_files`). Los ficheros bajo `/var/lib/kubelet/` y `/var/lib/docker/` se ignoran automáticamente.

---

### 🛡️ Control de Acceso Obligatorio (MAC)

| ID | Qué verifica | Severidad | Fix automático |
|----|-------------|-----------|----------------|
| `apparmor_inactive` | AppArmor instalado pero no activo | Medium | ✅ `systemctl enable --now apparmor` |

**Nota:** Si el sistema usa SELinux en lugar de AppArmor, este check no aplica y no genera hallazgo.

---

### 📋 Auditoría del sistema

| ID | Qué verifica | Severidad | Fix automático |
|----|-------------|-----------|----------------|
| `no_auditd` | auditd no instalado | High | ✅ `apt install auditd && systemctl enable --now auditd` |
| `auditd_inactive` | auditd instalado pero inactivo | High | ✅ `systemctl enable --now auditd` |
| `no_aide` | AIDE (monitor de integridad) no instalado | High | ✅ `apt install aide` |
| `aide_db_missing` | AIDE instalado pero base de datos no inicializada | High | ✅ `aideinit` + renombrar DB |

---

### ⚠️ Servicios inseguros

Detecta servicios activos con vulnerabilidades conocidas o protocolos obsoletos:

| ID | Servicio | Por qué es inseguro | Severidad | Fix automático |
|----|---------|--------------------|-----------|----|
| `svc_telnet` | telnet | Credenciales en texto plano | High | ✅ `systemctl disable --now telnet` |
| `svc_rsh` | rsh | Sin cifrado, vulnerable | High | ✅ |
| `svc_rlogin` | rlogin | Sin cifrado, vulnerable | High | ✅ |
| `svc_finger` | finger | Expone información de usuarios | High | ✅ |
| `svc_talk` | talk | Protocolo obsoleto sin cifrado | High | ✅ |
| `svc_tftp` | tftp | Sin autenticación | High | ✅ |
| `svc_xinetd` | xinetd | Reemplazado por systemd | High | ✅ |
| `svc_nis` | nis | Protocolo obsoleto, vulnerable a MITM | High | ✅ |

---

### 🔑 Privilegios (sudo)

| ID | Qué verifica | Archivos | Severidad | Fix automático |
|----|-------------|---------|-----------|----------------|
| `sudoers_nopasswd_<archivo>_<línea>` | Entradas NOPASSWD en sudoers | `/etc/sudoers`, `/etc/sudoers.d/*` | High | ❌ Requiere revisión manual |

**Por qué no tiene fix automático:** Eliminar un NOPASSWD incorrecto podría romper scripts de automatización legítimos. Se reporta con la línea exacta para revisión manual.

---

### 🖥️ Sistema general

| ID | Qué verifica | Severidad | Fix automático |
|----|-------------|-----------|----------------|
| `core_dumps_enabled` | Core dumps no deshabilitados en `limits.conf` | Medium | ✅ Añade `* hard core 0` + `sysctl fs.suid_dumpable=0` |
| `usb_storage_enabled` | Módulo `usb-storage` no bloqueado | Medium | ✅ Crea `/etc/modprobe.d/cyberhound-usb.conf` |
| `ctrlaltdel_enabled` | Ctrl+Alt+Del puede reiniciar el sistema | Medium | ✅ `systemctl mask ctrl-alt-del.target` |
| `cron_unrestricted` | Sin `/etc/cron.allow` ni `/etc/cron.deny` | Low | ❌ Requiere definir usuarios autorizados |
| `no_unattended_upgrades` | Actualizaciones automáticas no configuradas | Medium | ✅ `apt install unattended-upgrades` + reconfigurar |

---

### 📊 Cálculo de la puntuación de seguridad

La puntuación (0-100) se calcula en el dashboard restando penalizaciones por cada hallazgo:

| Severidad | Penalización |
|-----------|-------------|
| Critical | -20 puntos |
| High | -10 puntos |
| Medium | -4 puntos |
| Low | -1 punto |
| Info | -0 puntos |

Una instalación limpia recién configurada suele tener entre 40-60 puntos. Aplicar todos los fixes automáticos típicamente lleva la puntuación por encima de 85.

---

### `core/models.py` — Modelos de datos

```python
@dataclass
class Finding:
    id:          str    # Identificador único
    category:    str    # "ssh", "firewall", "malware/yara"...
    severity:    str    # "critical"|"high"|"medium"|"low"|"info"
    title:       str    # Título legible
    description: str    # Descripción detallada
    remediation: str    # Cómo solucionarlo
    evidence:    str    # Evidencia técnica
    auto_fix:    bool   # True si hay corrección automática
    file_path:   str    # Ruta del fichero afectado
    line_number: int    # Línea (para code audit)
    source_host: str    # Host de origen (SSH/network scan)
```

### `core/auth.py` — Autenticación

Tres modos configurables:
- **`jwt`** (por defecto): Token JWT HS256, cookie httponly, SameSite=Strict
- **`basic`**: HTTP Basic Auth sobre HTTPS
- **`none`**: Sin auth, solo localhost

### `core/executor.py` — Ejecución de comandos

- `run_command()`: async con timeout obligatorio
- `read_file_async()`: sin bloquear el event loop
- `find_files_async()`: búsqueda en background
- Los errores de permisos SELinux/AppArmor se loguean, nunca se silencian

### `scanners/hardening.py` — Fixes disponibles

| Finding ID | Acción automática |
|-----------|------------------|
| `ssh_PermitRootLogin` | sed en sshd_config + reload |
| `fw_ufw_inactive` | `ufw --force enable` |
| `kernel_*` | `sysctl -w` + persistencia |
| `ww_*` | `chmod o-w <fichero>` |
| `no_pam_faillock` | Inserta línea en common-auth |
| `svc_*` | `systemctl disable --now` |
| `login_defs_*` | Edita `/etc/login.defs` |
| `ctrlaltdel_enabled` | `systemctl mask ctrl-alt-del.target` |
| `log_perm_*` | `chmod o-r <fichero>` |

### `scanners/network.py` — Nmap XML parsing

Parsea la salida XML de nmap para extraer:
- OS detection (nombre + % de confianza)
- Puertos abiertos con servicio, producto, versión y CPE
- CVEs via scripts NSE `vuln`
- MAC address y fabricante (OUI)

---

## API REST y WebSocket

### Endpoints REST

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| `GET` | `/health` | No | Healthcheck |
| `GET/POST` | `/login` | No | Autenticación |
| `GET` | `/logout` | — | Cerrar sesión |
| `GET` | `/ws` | Sí | WebSocket streaming |
| `POST` | `/api/fix/local` | Sí | Fix local |
| `POST` | `/api/fix/remote` | Sí | Fix remoto SSH |
| `POST` | `/api/report/html` | Sí | Informe HTML |
| `POST` | `/api/report/ansible` | Sí | Playbook Ansible |
| `GET/POST` | `/api/config/keys` | Sí | API keys |
| `GET` | `/api/network/discover` | Sí | Descubrir hosts |

### WebSocket — Protocolo

**Cliente → Servidor:**
```json
{ "task": "audit" }
{ "task": "malware", "skip": ["hash"], "yara_rules": "/ruta/" }
{ "task": "network", "networks": "192.168.1.0/24", "ssh_user": "root", "ssh_audit": true }
{ "task": "ssh", "hosts": "192.168.1.10,192.168.1.20", "ssh_key": "/ruta/clave" }
{ "task": "code", "path": "/var/www/html" }
{ "task": "intel", "target": "1.2.3.4", "modules": ["shodan", "virustotal"] }
```

**Servidor → Cliente (streaming):**
```json
{ "type": "log",         "level": "info", "text": "Iniciando audit..." }
{ "type": "finding",     "data": { Finding } }
{ "type": "devices",     "data": [ NetworkDevice ] }
{ "type": "host_result", "data": { "host": "...", "status": "ok", "count": 12 } }
{ "type": "done",        "count": 42 }
{ "type": "error",       "text": "Descripción del error" }
```

---

## Seguridad

### Medidas implementadas

| Área | Medida |
|------|--------|
| **Auth** | JWT HS256, cookie httponly+SameSite, TTL configurable |
| **Headers HTTP** | X-Frame-Options, X-Content-Type-Options, CSP, Cache-Control: no-store |
| **SSH** | asyncssh (sin sshpass), credenciales en memoria |
| **Fixes remotos** | Whitelist de comandos (chmod, systemctl, sysctl, sed, ufw, apt-get) |
| **Logging** | `security_audit.log` separado: logins, fixes, scans |
| **Errores** | Permisos SELinux/AppArmor logueados, nunca silenciados |
| **Instalación** | venv aislado, sin `--break-system-packages` |

### Log de auditoría

`/var/log/cyberhound/security_audit.log` registra:
- Login exitoso/fallido con IP de origen
- Cada fix aplicado (finding ID, usuario, host, dry-run)
- Cada escaneo iniciado

---

## Configuración

`/root/.cyberhound/config.yaml`:

```yaml
auth:
  mode: jwt                     # jwt | basic | none
  username: admin
  password_hash: "sha256hex"    # cyberhound setup para generarlo
  token_ttl_hours: 8

server:
  host: "0.0.0.0"
  port: 8443
  tls_cert: "/etc/ssl/certs/ch.pem"   # opcional — activa HTTPS
  tls_key: "/etc/ssl/private/ch.key"

api_keys:
  shodan:     ""
  virustotal: ""
  abuseipdb:  ""

scan:
  ssh_key_path: "~/.ssh/id_ed25519"
  ssh_default_user: root
  ssh_default_port: 22
  ssh_concurrency: 5
  max_ww_files: 200
  hash_scan_max: 50
  nmap_timeout: 180
```

---

## Herramientas recomendadas

| Herramienta | Función | Instalación |
|-------------|---------|-------------|
| `nmap` | Network scan, OS detection, CVEs | `sudo apt install nmap` |
| `arp-scan` | Descubrimiento LAN | `sudo apt install arp-scan` |
| `gitleaks` | Secretos en código | [github.com/gitleaks](https://github.com/gitleaks/gitleaks/releases) |
| `shellcheck` | Análisis Bash | `sudo apt install shellcheck` |
| `bandit` | Análisis Python | `pip install bandit` |
| `semgrep` | Análisis multi-lenguaje | `pip install semgrep` |
| `trufflehog` | Secretos verificados | [github.com/trufflesecurity](https://github.com/trufflesecurity/trufflehog/releases) |

---

## Contribuir

### Añadir un nuevo check de hardening

```python
# En scanners/hardening.py

async def check_mi_check() -> list[Finding]:
    content = await read_file_async("/etc/fichero")
    if content and "patron_inseguro" in content:
        return [_f(
            id="mi_check_id",
            category="categoria",
            severity="high",
            title="Descripción del problema",
            description="Explicación para el usuario",
            remediation="comando --corrector",
            auto_fix=True,
        )]
    return []

# Añadir a HardeningAuditor.CHECKS
# Si auto_fix=True, añadir en HardeningFixer.fix() y _fix_mi_check()
```

### Añadir un módulo de malware

```python
# En scanners/malware.py

async def scan_mi_modulo() -> list[Finding]:
    findings = []
    # lógica de detección
    return findings

# Añadir en MalwareScanner.full_scan():
if "mi_modulo" not in skip:
    tasks["mi_modulo"] = scan_mi_modulo()
```

### Tests

```bash
# Verificar sintaxis de todos los módulos
python -m py_compile cyberhound/**/*.py cyberhound/*.py

# Verificar imports
python -c "
from cyberhound.core.models import Finding
from cyberhound.core.auth import AuthConfig
from cyberhound.scanners.hardening import HardeningAuditor
from cyberhound.api.server import CyberHoundServer
print('OK')
"
```

---

## Roadmap

### v6.1
- [ ] Tests unitarios (pytest + pytest-asyncio)
- [ ] TLS auto-firmado en primer arranque
- [ ] Notificaciones email/Slack para hallazgos críticos
- [ ] Scheduler para auditorías periódicas automáticas
- [ ] Histórico: evolución de la puntuación de seguridad

### v6.2
- [ ] Integración con Wazuh/OSSEC
- [ ] Análisis de Active Directory / LDAP
- [ ] Soporte Windows vía PowerShell remoting
- [ ] Dashboard multi-tenant para MSPs

### v7.0
- [ ] Arquitectura de microservicios
- [ ] Base de datos PostgreSQL para histórico
- [ ] Monitorización continua con inotify/eBPF
- [ ] Actualización automática de reglas YARA

---

## Licencia

MIT License — ver [LICENSE](LICENSE)

---

*Desarrollado para hacer la ciberseguridad accesible a las PYMEs* 🐾
