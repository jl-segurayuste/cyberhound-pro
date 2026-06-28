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
