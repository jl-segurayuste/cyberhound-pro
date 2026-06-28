# CyberHound Pro

**Plataforma de auditoría, seguridad y monitoreo continuo para PYMEs**

> Analiza tu red, servidores, contenedores y código. Detecta vulnerabilidades, malware y configuraciones inseguras. Corrige automáticamente. Monitoriza en tiempo real.

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-505%20passed-green.svg)](#tests)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

---

## Índice

- [¿Qué hace?](#qué-hace)
- [Instalación rápida](#instalación-rápida)
- [Funcionalidades](#funcionalidades)
- [Arquitectura](#arquitectura)
- [Checks de hardening](#checks-de-hardening-26-checks)
- [Checks Docker y Kubernetes](#checks-docker-y-kubernetes)
- [API REST y WebSocket](#api-rest-y-websocket)
- [Seguridad implementada](#seguridad-implementada)
- [SIEM — Integración externa](#siem--integración-externa)
- [Configuración](#configuración)
- [Tests](#tests)
- [Roadmap](#roadmap)

---

## ¿Qué hace?

CyberHound Pro es una herramienta todo-en-uno de ciberseguridad orientada a entornos Linux sin equipo de seguridad dedicado:

| Módulo | Descripción |
|--------|-------------|
| **🔍 Hardening Audit** | 26 checks de configuración con corrección automática |
| **📡 Network Scan** | Descubrimiento de red, OS detection, CVEs via nmap |
| **🖥️ SSH Audit** | Audit remoto de múltiples hosts en paralelo |
| **🦠 Malware Scan** | YARA, hashes (VT/MalwareBazaar), auditd, cron, webshells |
| **🐳 Docker + K8s** | 7 checks Docker + 11 checks Kubernetes |
| **📝 Code Audit** | bandit, shellcheck, eslint + detección de secretos |
| **🌐 Intel** | Shodan, VirusTotal, AbuseIPDB, GreyNoise, HIBP |
| **📊 Scoring** | Score contextual 0-100 con factor de exposición |
| **📡 Monitoreo** | Panel de actividad en tiempo real, alertas automáticas |
| **🛡 SIEM** | Wazuh, Elasticsearch, Splunk HEC |

---

## Instalación rápida

### Docker (recomendado)

```bash
git clone https://github.com/jl-segurayuste/cyberhound-pro.git
cd cyberhound-pro
cp .env.example .env
nano .env        # Cambiar CH_PASSWORD
docker compose up -d
# Abrir https://localhost:8443
```

### Manual (Linux)

```bash
git clone https://github.com/jl-segurayuste/cyberhound-pro.git
cd cyberhound-pro
chmod +x install.sh && ./install.sh
sudo cyberhound web --port 8443
```

**Cambiar contraseña:**
```bash
sudo cyberhound setup
```

---

## Funcionalidades

### Panel de actividad en tiempo real

El panel lateral muestra en tiempo real cada hallazgo conforme se detecta, con:
- Icono de severidad (🔴 crítico, 🟠 alto, 🟡 medio, 🔵 bajo)
- Barra de progreso animada por cada scan activo
- Contadores en tiempo real (críticos, altos, medios)
- Apertura automática cuando aparece un hallazgo crítico
- Monitoreo periódico de nuevos dispositivos en la red (cada 15 min)

### Escaneos paralelos

Puedes ejecutar múltiples análisis simultáneamente:
- Lanzar Docker scan mientras corre el Network scan
- Malware scan en segundo plano mientras revisas resultados del audit
- Cada scan tiene su propia barra de progreso independiente

### Scoring contextual (0-100)

El score no es una simple resta de puntos — tiene en cuenta:

| Factor | Impacto |
|--------|---------|
| Categoría | `docker/escape` ×2.0, `ssh` ×1.5, `updates` ×0.7 |
| Exposición | Internet-facing +40%, web server +20% |
| Auto-fix disponible | Penalización -25% (el riesgo es manejable) |
| Acumulación | El décimo finding del mismo tipo pesa ×0.8^9 menos |
| Bonus | +2pts si SSH bien configurado, +2pts si firewall OK |

Grades: **A** (≥90) · **B** (≥75) · **C** (≥60) · **D** (≥40) · **F** (<40)

### Corrección automática

Los hallazgos con ⚡ pueden corregirse con un clic, tanto en local como en hosts remotos vía SSH:

| Categoría | Ejemplos de fixes |
|-----------|------------------|
| SSH | PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 4 |
| Firewall | ufw enable, systemctl enable --now firewalld |
| Kernel | sysctl -w + persistencia en /etc/sysctl.d/ |
| Auth | pam_faillock, login.defs policy |
| Sistema | ctrl-alt-del mask, USB blacklist, core dumps off |
| Banners | Crear /etc/issue, /etc/issue.net, /etc/motd |
| NTP | apt install chrony + enable |
| OpenSSH CVE | apt upgrade openssh-server |

---

## Arquitectura

```
cyberhound/
├── __main__.py              # CLI: web / setup / version
├── pyproject.toml           # v6.1.0, deps, pytest config
│
├── core/
│   ├── models.py            # Finding, HostResult, ScanReport
│   ├── config.py            # YAML + env vars + validate() eager
│   ├── auth.py              # JWT HS256 + rate limiting + CSRF
│   ├── security.py          # RateLimiter, InputValidator, TLSManager, CSRF
│   ├── logging.py           # JSON estructurado + journald + SecurityAuditLogger
│   ├── executor.py          # Comandos async + ThreadPoolExecutor
│   ├── database.py          # SQLite WAL: scans, findings, assets, suppressions, users
│   ├── scheduler.py         # Loop asyncio: audit 02:00, malware lun 03:00, network 04:00
│   ├── notifications.py     # Email SMTP+TLS + webhooks Slack/Teams
│   ├── scoring.py           # Motor de scoring contextual (5 factores)
│   └── siem.py              # Wazuh UDP/API + Elasticsearch + Splunk HEC
│
├── scanners/
│   ├── hardening.py         # 26 checks + HardeningFixer (todos los fixes)
│   ├── malware.py           # YARA + MalwareBazaar/VT + auditd + cron + webshells
│   ├── network.py           # nmap XML, OS detection, CVEs, risk level
│   ├── ssh_audit.py         # asyncssh, SFTP para script remoto, whitelist fixes
│   ├── docker_scan.py       # 7 checks Docker + integración K8s
│   ├── kubernetes_scan.py   # 11 checks Kubernetes via kubectl
│   ├── code.py              # bandit + shellcheck + eslint
│   ├── secrets.py           # gitleaks → trufflehog → semgrep → regex
│   ├── intel.py             # Shodan, VT, AbuseIPDB, GreyNoise, OTX, HIBP
│   ├── nuclei_scan.py       # motor Nuclei (ProjectDiscovery) → Finding normalizado
│   └── reports.py           # HTML + Ansible playbook
│
├── api/
│   └── server.py            # aiohttp + WebSocket streaming + 25+ endpoints REST
│
└── ui/static/
    ├── index.html           # SPA — 9 secciones + panel de actividad
    ├── style.css            # Dark theme corporativo
    └── app.js               # WebSocket, dashboard, scoring, actividad en tiempo real
```

---

## Checks de hardening (26 checks)

### SSH (`/etc/ssh/sshd_config`)
| ID | Verifica | Fix |
|----|---------|-----|
| `ssh_PermitRootLogin` | PermitRootLogin yes | ✅ |
| `ssh_PasswordAuthentication` | PasswordAuthentication yes | ✅ |
| `ssh_PermitEmptyPasswords` | PermitEmptyPasswords yes | ✅ |
| `ssh_X11Forwarding` | X11Forwarding yes | ✅ |
| `ssh_MaxAuthTries` | MaxAuthTries > 4 | ✅ |
| `ssh_protocol1` | Protocol 1 activo | ✅ |

### Firewall
| ID | Verifica | Fix |
|----|---------|-----|
| `fw_ufw_inactive` | UFW instalado pero inactivo | ✅ |
| `fw_firewalld_inactive` | firewalld inactivo | ✅ |
| `fw_none` | Sin firewall detectado | ❌ manual |

### Kernel (`/proc/sys/`)
10 parámetros: ASLR, SYN cookies, IP forwarding, ICMP redirects, source routing, log martians, rp_filter, dmesg_restrict, perf_event_paranoid, IPv6. Todos con fix automático vía sysctl + persistencia.

### Autenticación y contraseñas
| ID | Verifica | Fix |
|----|---------|-----|
| `no_pam_faillock` | pam_faillock no configurado | ✅ |
| `login_defs_PASS_MAX_DAYS` | > 90 días | ✅ |
| `login_defs_PASS_MIN_DAYS` | < 1 día | ✅ |
| `login_defs_PASS_WARN_AGE` | < 7 días aviso | ✅ |
| `login_defs_LOGIN_RETRIES` | > 5 reintentos | ✅ |

### Sistema general
| ID | Verifica | Fix |
|----|---------|-----|
| `check_umask` | umask 022 en /etc/profile | ✅ |
| `no_ntp` | Sin NTP/chrony activo | ✅ |
| `no_banner_*` | Banners de login vacíos | ✅ |
| `empty_password_*` | Cuentas sin contraseña en /etc/shadow | ✅ bloquear |
| `duplicate_uid0_*` | UID 0 en cuenta que no es root | ❌ manual |
| `tmp_*_noexec` | /tmp sin noexec/nosuid | ❌ manual |
| `tmp_no_sticky_bit` | /tmp sin sticky bit | ✅ |
| `svc_listen_all_*` | Servicios DB/cache en 0.0.0.0 | ❌ manual |
| `openssh_cve_*` | Versión OpenSSH con CVEs conocidos | ✅ apt upgrade |
| `ww_*` | Ficheros world-writable | ✅ chmod o-w |
| `log_perm_*` | Logs legibles por todos | ✅ chmod o-r |
| `no_auditd` | auditd no instalado/activo | ✅ |
| `no_aide` | AIDE no instalado | ✅ |
| `apparmor_inactive` | AppArmor inactivo | ✅ |
| `core_dumps_enabled` | Core dumps activos | ✅ |
| `usb_storage_enabled` | USB storage no bloqueado | ✅ |
| `ctrlaltdel_enabled` | Ctrl+Alt+Del habilitado | ✅ |
| `no_unattended_upgrades` | Updates automáticos no configurados | ✅ |

---

## Checks Docker y Kubernetes

### Docker (7 checks)
| Check | Severidad | Descripción |
|-------|-----------|-------------|
| `containers_root` | High | Contenedores sin runAsUser ni User definido |
| `privileged` | Critical | Contenedores con `--privileged` |
| `docker_socket` | Critical | `/var/run/docker.sock` montado |
| `env_secrets` | High | Credenciales en variables de entorno |
| `dangerous_mounts` | Critical | Rutas del host como `/etc`, `/proc`, `/` montadas |
| `old_images` | Medium | Imágenes con más de 90 días sin actualizar |
| `images_cve` | Critical/High | CVEs en imágenes (requiere Trivy) |

### Kubernetes (11 checks via kubectl)
| Check | Severidad | Descripción |
|-------|-----------|-------------|
| `pods_as_root` | High | Pods sin `runAsNonRoot: true` |
| `privileged_pods` | Critical | Contenedores con `privileged: true` |
| `rbac_wildcards` | Critical | ClusterRoles con permisos `*` |
| `automount_service_account` | Medium | Token ServiceAccount no desactivado |
| `no_network_policy` | High | Namespaces sin NetworkPolicy |
| `no_resource_limits` | Medium | Contenedores sin límites CPU/memoria |
| `latest_image_tag` | Low | Imágenes con tag `:latest` |
| `env_secrets` | High | Secretos hardcodeados en env vars |
| `dangerous_hostpath` | Critical | HostPath con rutas peligrosas del host |
| `kubernetes_version` | High | Versión de K8s con CVEs conocidos |
| `pod_security_standards` | Medium | Namespaces sin Pod Security Admission |

---

## API REST y WebSocket

### Endpoints principales

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET/POST` | `/login` | Autenticación |
| `GET` | `/ws` | WebSocket streaming de scans |
| `GET` | `/health` | Healthcheck |
| `GET` | `/api/dashboard` | Stats del dashboard |
| `GET` | `/api/history` | Histórico de scans |
| `GET` | `/api/history/{id}/compare` | Comparación entre scans |
| `GET` | `/api/score/trend` | Tendencia de score 30 días |
| `GET` | `/api/score/detail` | Desglose contextual del score |
| `GET/POST` | `/api/assets` | Inventario de dispositivos |
| `POST` | `/api/assets/{ip}/authorize` | Autorizar/denegar dispositivo |
| `GET/POST/DELETE` | `/api/suppressions` | Gestión de falsos positivos |
| `GET/POST/PATCH/DELETE` | `/api/users` | Gestión de usuarios |
| `GET/POST` | `/api/scheduler/{name}/run` | Scheduler de tareas |
| `POST` | `/api/fix/local` | Aplicar fix local |
| `POST` | `/api/fix/remote` | Aplicar fix remoto via SSH |
| `POST` | `/api/report/{html\|ansible}` | Generar informes |
| `GET/POST` | `/api/config/keys` | API keys |
| `GET/POST` | `/api/config/notifications` | Config notificaciones |
| `GET/POST` | `/api/config/siem` | Config SIEM |
| `POST` | `/api/config/siem/test` | Test de conectividad SIEM |

### Tareas WebSocket disponibles

```json
{ "task": "audit" }
{ "task": "malware", "skip": ["hash"], "yara_rules": "/ruta/" }
{ "task": "network", "networks": "192.168.1.0/24", "ssh_audit": true }
{ "task": "ssh", "hosts": "192.168.1.10,192.168.1.20", "ssh_key": "/ruta" }
{ "task": "docker", "scan_images_cve": true, "scan_k8s": true }
{ "task": "code", "path": "/var/www/html" }
{ "task": "intel", "target": "1.2.3.4", "modules": ["shodan","virustotal"] }
```

---

## Seguridad implementada

### Autenticación y sesión
- **JWT HS256** con secreto persistente en `config.yaml` (permisos 600)
- **Cookie** `httponly` + `SameSite=Strict` + `Secure` (dinámico según TLS)
- **Rate limiting**: 5 intentos/15min → bloqueo 15min/1h/24h (exponencial)
- **Rate limiting** nunca bloquea localhost
- **CSRF**: double-submit cookie en formularios POST; `/api/*` exentas (JWT)
- **JWT expirado**: redirige al login limpiando la cookie inválida

### TLS automático
- Certificado RSA 4096 auto-firmado generado en el primer arranque
- TLS 1.2+ obligatorio, cifrados modernos únicamente (ECDHE+AES-GCM, ChaCha20)
- Soporte de certificados externos (Let's Encrypt compatible)

### Validación de inputs
- `InputValidator.ws_message()`: whitelist de tareas, bloqueo de path traversal
- IPs validadas con `ipaddress.ip_address()` (no regex — evita falsos positivos)
- CIDRs máximo /16 (no se permiten /8 o más grandes)
- Máximo 50 hosts por scan, máximo 5 redes por petición

### Headers HTTP
`X-Content-Type-Options`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `CSP`, `Cache-Control: no-store`

### Logging de auditoría
`/var/log/cyberhound/security_audit.log`: logins, fixes aplicados, scans iniciados

---

## SIEM — Integración externa

Envío automático de findings en tiempo real a:

### Wazuh
- **UDP socket** (agente activo, puerto 1514)
- **API REST** del Wazuh Manager (opcional)
- Formato compatible con decoders custom de Wazuh

### Elasticsearch / ELK
- Indexación directa en el índice configurado
- Autenticación: API Key o usuario/contraseña
- Índice por defecto: `cyberhound-findings`

### Splunk HEC
- HTTP Event Collector
- Token configurable, índice y sourcetype configurables

**Configuración** desde la UI: ⚙️ Config → 🛡 SIEM

---

## Configuración

`~/.cyberhound/config.yaml` (o `/root/.cyberhound/config.yaml` con sudo):

```yaml
auth:
  mode: jwt
  username: admin
  password_hash: "sha256hex"    # cyberhound setup
  secret: "hex32chars"          # persistido automáticamente
  token_ttl_hours: 8

server:
  host: "0.0.0.0"
  port: 8443
  tls_cert: null    # null = auto-firmado
  tls_key: null

scan:
  ssh_key_path: "~/.ssh/id_ed25519"
  ssh_default_user: root
  ssh_concurrency: 5
  max_ww_files: 200

scheduler:
  enabled: true
  audit_hour: 2        # audit diario 02:00
  malware_day: 0       # malware los lunes (0=lunes)
  malware_hour: 3
  network_hour: 4

notifications:
  email_enabled: false
  smtp_host: smtp.gmail.com
  min_level: warning   # info | warning | critical

siem:
  wazuh_enabled: false
  elk_enabled: false
  splunk_enabled: false
  min_severity: medium
```

### Variables de entorno (Docker)

| Variable | Descripción |
|----------|-------------|
| `CH_PASSWORD` | Contraseña de acceso |
| `CH_USERNAME` | Usuario (defecto: admin) |
| `SHODAN_API_KEY` | API key de Shodan |
| `VT_API_KEY` | API key de VirusTotal |
| `CH_SMTP_PASSWORD` | Contraseña SMTP (no en YAML) |
| `CH_WAZUH_PASS` | Contraseña API Wazuh |
| `CH_ELK_API_KEY` | API key Elasticsearch |
| `CH_SPLUNK_TOKEN` | Token Splunk HEC |

---

## Tests

**195 tests** distribuidos en 7 ficheros:

```bash
# Ejecutar todos los tests
pytest tests/ -v

# Con cobertura
pytest tests/ --cov=cyberhound --cov-report=term-missing
```

| Fichero | Tests | Cobertura |
|---------|-------|-----------|
| `test_security.py` | 45 | RateLimiter, InputValidator, TLS |
| `test_database.py` | 40 | Scans, assets, supresiones, usuarios, stats |
| `test_hardening.py` | 22 | Checks individuales + HardeningFixer |
| `test_scheduler.py` | 13 | Scheduler, entries, run_now |
| `test_scoring.py` | 25 | Motor de scoring, contexto, grades |
| `test_config.py` | 22 | Validación eager, save/reload |
| `test_docker_k8s.py` | 28 | Docker y Kubernetes checks |

---

## Herramientas del sistema recomendadas

| Herramienta | Para qué | Instalación |
|-------------|---------|-------------|
| `nmap` | Network scan, OS detection, CVEs | `sudo apt install nmap` |
| `arp-scan` | Descubrimiento LAN | `sudo apt install arp-scan` |
| `kubectl` | Kubernetes scan | [kubernetes.io/docs](https://kubernetes.io/docs/tasks/tools/) |
| `trivy` | CVEs en imágenes Docker | [aquasecurity.github.io](https://aquasecurity.github.io/trivy/) |
| `gitleaks` | Secretos en código | [github.com/gitleaks](https://github.com/gitleaks/gitleaks/releases) |
| `shellcheck` | Análisis Bash | `sudo apt install shellcheck` |
| `bandit` | Análisis Python | `pip install bandit` |
| `semgrep` | Análisis multi-lenguaje | `pip install semgrep` |
| `auditd` | Logging kernel | `sudo apt install auditd` |

---

## Roadmap

### ✅ Implementado en v6.3 — Funcionalidades completas

| Área | Módulo | Detalle |
|------|--------|---------|
| Auditoría | `hardening.py` | 26 checks + corrección automática |
| Red | `network.py` | nmap, OS detection, CVEs en red |
| SSH | `ssh_audit.py` | audit remoto paralelo, SFTP |
| Malware | `malware.py` | YARA streaming O(1), VT, webshells |
| Docker | `docker_scan.py` | 7 checks de configuración |
| Kubernetes | `kubernetes_scan.py` | 11 checks via kubectl |
| Docker image | `docker_image_scan.py` | Secretos en capas, SUID, EOL |
| Runtime | `runtime_scan.py` | Procesos, diff, red, CPU en vivo |
| Servicios | `services_audit.py` | nginx, apache, mysql, pg, redis, mongodb |
| TLS/SSL | `tls_scan.py` | expiración, autofirmados, protocolos/firmas/claves débiles |
| Cabeceras web | `web_headers.py` | HSTS, CSP, X-Frame, cookies inseguras, fuga de info |
| DNS security | `dns_security.py` | SPF, DMARC, DKIM, DNSSEC, CAA |
| Código | `code.py` | bandit, shellcheck, eslint, secretos |
| Intel | `intel.py` | Shodan, VT, AbuseIPDB, GreyNoise, HIBP |
| LDAP/AD | `ldap_audit.py` | 6 checks: AS-REP, domain admins, policy |
| Scoring | `scoring.py` | 5 factores, grades A-F, exposición |
| PDF | `pdf_report.py` | fpdf2 + compliance ENS/ISO en el informe |
| Compliance | `compliance.py` | ENS, ISO 27001, PCI-DSS, CIS Controls v8 |
| SBOM | `sbom.py` | CycloneDX 1.4, SPDX 2.3, diff entre scans |
| Cuarentena | `quarantine.py` | XOR + restore con verificación SHA-256 |
| Monitor | `ebpf_monitor.py` | eBPF/auditd: 12 patrones, 14 ficheros |
| 2FA | `totp.py` | TOTP RFC 6238, recovery codes |
| Licencias | `licensing.py` | community/starter/professional/enterprise |
| Agentes | `agent.py` | Multi-servidor con heartbeat |
| Multi-tenant | `multitenancy.py` | TenantStore, middleware, API key por tenant |
| OpenAPI | `openapi.py` | Spec 3.0.3 + Swagger UI en /api/docs |
| Ansible | `ansible_integration.py` | Playbooks auto + AWX/Tower API |
| BD | `database.py` + `database_pg.py` | SQLite WAL + PostgreSQL asyncpg |
| SIEM | `siem.py` + `wazuh/` | Wazuh (decoders+reglas), ELK, Splunk |
| Push | WS `/ws/push` | Notificaciones en tiempo real sin polling |
| CSS | `style.css` | Responsive mobile/tablet/print |
| Tests | `tests/` | **355 tests pytest** |

### 🔜 Ideas para futuras versiones

- **Compliance en tiempo real** — alertas cuando un check baja el score de un marco normativo
- **Integración con ticketing** — Jira/ServiceNow automático desde hallazgos críticos
- **ML scoring** — modelo entrenado con datos históricos para priorización más inteligente
- **App móvil nativa** — iOS/Android con notificaciones push reales
- **Marketplace de reglas YARA** — repositorio centralizado con actualización automática
- **Exportación a Elastic Security** — timeline de incidentes y correlation rules


## Licencia

AGPL-3.0 License — ver [LICENSE](LICENSE). Copyright © 2026 José Luis Segura Yuste.

*Desarrollado para hacer la ciberseguridad accesible a las PYMEs*
