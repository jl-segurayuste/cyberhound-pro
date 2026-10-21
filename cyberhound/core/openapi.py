"""
Documentación OpenAPI 3.0 para CyberHound Pro.

Genera automáticamente el spec OpenAPI a partir de las rutas registradas
en aiohttp y metadatos adicionales decoradores/dicts por endpoint.

El spec se sirve en /api/openapi.json y la UI en /api/docs (Swagger UI).
"""
from __future__ import annotations

from typing import Any

from cyberhound import __version__

# ── Metadatos de endpoints ────────────────────────────────────────────────────

ENDPOINT_DOCS: dict[str, dict] = {
    "GET /api/dashboard": {
        "summary": "Estadísticas del dashboard",
        "description": "Devuelve métricas globales: último scan de cada tipo, score, activos, tendencia.",
        "tags": ["Dashboard"],
        "responses": {
            "200": {"description": "Stats del dashboard", "schema": "DashboardStats"}
        },
    },
    "GET /api/history": {
        "summary": "Historial de scans",
        "tags": ["Scans"],
        "parameters": [
            {"name": "type", "in": "query", "description": "Filtrar por tipo (audit, malware, network…)"},
            {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
        ],
    },
    "GET /api/history/{scan_id}": {
        "summary": "Findings de un scan",
        "tags": ["Scans"],
        "parameters": [{"name": "scan_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
    },
    "GET /api/history/{scan_id}/compare": {
        "summary": "Comparación con el scan anterior",
        "tags": ["Scans"],
        "description": "Devuelve hallazgos nuevos, resueltos y sin cambio respecto al scan previo del mismo tipo.",
    },
    "GET /api/score/trend": {
        "summary": "Tendencia del score",
        "tags": ["Scoring"],
        "parameters": [
            {"name": "type", "in": "query", "default": "audit"},
            {"name": "days", "in": "query", "schema": {"type": "integer", "default": 30}},
        ],
    },
    "GET /api/score/detail": {
        "summary": "Desglose contextual del score",
        "tags": ["Scoring"],
    },
    "GET /api/assets": {
        "summary": "Inventario de dispositivos",
        "tags": ["Assets"],
        "description": "Lista todos los activos descubiertos en la red.",
    },
    "POST /api/assets/{ip}/authorize": {
        "summary": "Autorizar / denegar dispositivo",
        "tags": ["Assets"],
        "requestBody": {
            "properties": {
                "authorized": {"type": "boolean"},
                "notes": {"type": "string"},
            }
        },
    },
    "GET /api/suppressions": {"summary": "Listar supresiones", "tags": ["Suppressions"]},
    "POST /api/suppressions": {
        "summary": "Crear supresión",
        "tags": ["Suppressions"],
        "requestBody": {
            "required": True,
            "properties": {
                "pattern": {"type": "string", "description": "Patrón glob (e.g. ssh_*)"},
                "reason": {"type": "string"},
                "expires_at": {"type": "string", "format": "date-time"},
            },
        },
    },
    "DELETE /api/suppressions/{pattern}": {
        "summary": "Eliminar supresión",
        "tags": ["Suppressions"],
    },
    "GET /api/users": {"summary": "Listar usuarios", "tags": ["Users"]},
    "POST /api/users": {
        "summary": "Crear usuario",
        "tags": ["Users"],
        "requestBody": {
            "required": True,
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
                "role": {"type": "string", "enum": ["admin", "operator", "viewer"]},
            },
        },
    },
    "POST /api/fix/local": {
        "summary": "Aplicar corrección automática en local",
        "tags": ["Remediation"],
        "requestBody": {
            "required": True,
            "properties": {
                "finding_id": {"type": "string"},
                "scan_id": {"type": "integer"},
            },
        },
    },
    "POST /api/fix/remote": {
        "summary": "Aplicar corrección en host remoto vía SSH",
        "tags": ["Remediation"],
        "requestBody": {
            "required": True,
            "properties": {
                "finding_id": {"type": "string"},
                "host": {"type": "string"},
                "ssh_key": {"type": "string"},
            },
        },
    },
    "GET /api/fix/remote/history": {"summary": "Fixes remotos aplicados y si se pueden deshacer", "tags": ["Remediation"]},
    "POST /api/fix/remote/undo": {"summary": "Deshacer un fix remoto (vuelve al estado previo del host)", "tags": ["Remediation"],
                                  "requestBody": {"properties": {"fix_id": {"type": "string"},
                                                                 "ssh_user": {"type": "string"},
                                                                 "ssh_password": {"type": "string"}}}},
    "POST /api/report/pdf": {
        "summary": "Generar informe PDF",
        "tags": ["Reports"],
        "description": "Genera un informe PDF del último scan o del scan especificado. Incluye compliance ENS/ISO.",
        "requestBody": {
            "properties": {
                "scan_id": {"type": "integer"},
                "scan_type": {"type": "string", "default": "audit"},
                "target": {"type": "string", "default": "localhost"},
            },
        },
        "responses": {
            "200": {
                "description": "PDF o HTML según disponibilidad de fpdf2",
                "content": {"application/pdf": {}, "text/html": {}},
            }
        },
    },
    "POST /api/compliance": {
        "summary": "Análisis de cumplimiento normativo",
        "tags": ["Compliance"],
        "requestBody": {
            "properties": {
                "scan_id": {"type": "integer"},
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["ens", "iso27001", "pci-dss", "cis"]},
                },
            },
        },
    },
    "GET /api/compliance": {
        "summary": "Compliance del último audit",
        "tags": ["Compliance"],
        "parameters": [
            {"name": "frameworks", "in": "query", "description": "Comma-separated: ens,iso27001,cis"},
        ],
    },
    "POST /api/sbom/generate": {
        "summary": "Generar SBOM",
        "tags": ["SBOM"],
        "requestBody": {
            "properties": {
                "include": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["dpkg", "rpm", "pip", "npm", "docker", "kernel"]},
                },
                "format": {"type": "string", "enum": ["json", "cyclonedx", "spdx"]},
            },
        },
    },
    "GET /api/sbom/latest": {"summary": "SBOM más reciente", "tags": ["SBOM"]},
    "POST /api/scan/ldap": {
        "summary": "Análisis LDAP/Active Directory",
        "tags": ["Scans"],
        "requestBody": {
            "properties": {
                "uri":    {"type": "string", "description": "ldap://dc.empresa.local (vacío = autodetectar)"},
                "base":   {"type": "string", "description": "DC=empresa,DC=local"},
                "binddn": {"type": "string"},
                "bindpw": {"type": "string"},
            },
        },
    },
    "POST /api/scan/docker-image": {
        "summary": "Análisis profundo de imágenes Docker",
        "tags": ["Scans"],
        "requestBody": {
            "properties": {
                "images":      {"type": "array", "items": {"type": "string"}},
                "deep":        {"type": "boolean", "default": True},
                "max_images":  {"type": "integer", "default": 5},
                "max_size_mb": {"type": "integer", "default": 200},
            },
        },
    },
    "GET /api/quarantine": {"summary": "Listar cuarentena", "tags": ["Quarantine"]},
    "POST /api/quarantine": {
        "summary": "Enviar fichero a cuarentena",
        "tags": ["Quarantine"],
        "requestBody": {
            "required": True,
            "properties": {
                "filepath":    {"type": "string"},
                "finding_id":  {"type": "string"},
                "title":       {"type": "string"},
            },
        },
    },
    "POST /api/quarantine/{name}/restore": {
        "summary": "Restaurar fichero de cuarentena",
        "tags": ["Quarantine"],
    },
    "DELETE /api/quarantine/{name}": {
        "summary": "Eliminar permanentemente de cuarentena",
        "tags": ["Quarantine"],
    },
    "POST /api/auth/2fa/setup":    {"summary": "Iniciar configuración 2FA", "tags": ["Auth"]},
    "POST /api/auth/2fa/activate": {
        "summary": "Activar 2FA",
        "tags": ["Auth"],
        "requestBody": {
            "required": True,
            "properties": {"code": {"type": "string", "description": "Código TOTP de 6 dígitos"}},
        },
    },
    "POST /api/auth/2fa/disable":  {"summary": "Desactivar 2FA", "tags": ["Auth"]},
    "GET /api/auth/2fa/status":    {"summary": "Estado 2FA del usuario actual", "tags": ["Auth"]},
    "GET /api/agent/list":         {"summary": "Listar agentes remotos", "tags": ["Agent"]},
    "POST /api/agent/report":      {"summary": "Recibir report de agente (AgentKey auth)", "tags": ["Agent"]},
    "POST /api/agent/heartbeat":   {"summary": "Heartbeat de agente", "tags": ["Agent"]},
    "GET /api/monitor/status":     {"summary": "Estado del monitor eBPF/auditd", "tags": ["Monitor"]},
    "GET /api/yara/rules":         {"summary": "Listar reglas YARA instaladas", "tags": ["YARA"]},
    "POST /api/yara/update":       {
        "summary": "Actualizar reglas YARA desde repositorios públicos",
        "tags": ["YARA"],
        "requestBody": {
            "properties": {"sources": {"type": "array", "items": {"type": "string"}}},
        },
    },
    "POST /api/config/siem/test":  {"summary": "Test de conectividad SIEM", "tags": ["Config"]},
    "GET /ws": {
        "summary": "WebSocket de escaneo",
        "tags": ["WebSocket"],
        "description": "Lanza un análisis y recibe los hallazgos en tiempo real. Enviar {task: 'audit'|"
                       "'malware'|'network'|'ssh'|'docker'|'code'|'services'|'intel'|'tls'|'web_headers'|"
                       "'web_exposure'|'api_security'|'nuclei'|'dns'|'subdomain_enum', …parámetros}",
    },
    "GET /ws/push": {
        "summary": "WebSocket de notificaciones push",
        "tags": ["WebSocket"],
        "description": "Canal permanente de notificaciones. No requiere enviar mensajes. "
                       "Recibe eventos: new_findings, scan_complete, new_device.",
    },
    "POST /api/ansible/run":   {"summary": "Lanzar playbook Ansible", "tags": ["Ansible"]},
    "GET /api/ansible/jobs":   {"summary": "Listar jobs Ansible recientes", "tags": ["Ansible"]},
    "GET /api/tenants":        {"summary": "Listar tenants (modo multi-tenant)", "tags": ["MultiTenant"]},
    "POST /api/tenants":       {"summary": "Crear tenant (y opcionalmente su primer admin)", "tags": ["MultiTenant"],
                                "requestBody": {"required": True, "properties": {
                                    "slug": {"type": "string"}, "name": {"type": "string"},
                                    "admin_email": {"type": "string"}, "plan": {"type": "string"},
                                    "admin_username": {"type": "string"}, "admin_password": {"type": "string"}}}},

    # ── Sesión y plataforma ──────────────────────────────────────────────────
    "POST /login":             {"summary": "Iniciar sesión (formulario: username, password, _csrf; luego 2FA si está activo)",
                                "tags": ["Auth"]},
    "GET /logout":             {"summary": "Cerrar sesión", "tags": ["Auth"]},
    "GET /api/me":             {"summary": "Usuario de la sesión, rol y permisos", "tags": ["Auth"]},
    "POST /api/me/password":   {"summary": "Cambiar mi contraseña (cierra mis otras sesiones)", "tags": ["Auth"],
                                "requestBody": {"required": True, "properties": {"current": {"type": "string"},
                                                                                 "new": {"type": "string"}}}},
    "GET /api/sessions":       {"summary": "Mis sesiones abiertas", "tags": ["Auth"]},
    "DELETE /api/sessions/{jti}": {"summary": "Cerrar una de mis sesiones (id corto)", "tags": ["Auth"]},
    "POST /api/sessions/revoke-others": {"summary": "Cerrar todas mis sesiones menos la actual", "tags": ["Auth"]},
    "GET /api/tokens":         {"summary": "Mis tokens de API", "tags": ["Auth"]},
    "POST /api/tokens":        {"summary": "Crear token de API (el secreto solo se muestra una vez)", "tags": ["Auth"],
                                "requestBody": {"required": True, "properties": {
                                    "name": {"type": "string"},
                                    "role": {"type": "string", "enum": ["viewer", "operator", "admin"]},
                                    "expires_days": {"type": "integer", "description": "1-365; 0 = sin caducidad"}}}},
    "DELETE /api/tokens/{token_id}": {"summary": "Revocar un token de API", "tags": ["Auth"]},
    "GET /api/audit":          {"summary": "Eventos de auditoría de la organización (admin)", "tags": ["Auth"],
                                "parameters": [{"name": n, "in": "query"} for n in ("limit", "action", "user", "q", "failures")]},
    "DELETE /api/users/{username}/sessions": {"summary": "Cerrar todas las sesiones y tokens de un usuario", "tags": ["Users"]},
    "GET /health":             {"summary": "Healthcheck (sin autenticación)", "tags": ["Monitor"]},
    "GET /favicon.ico":        {"summary": "Icono (redirige a /static/favicon.svg)", "tags": ["Monitor"]},
    "GET /metrics":            {"summary": "Métricas en formato Prometheus", "tags": ["Monitor"]},
    "GET /api/openapi.json":   {"summary": "Esta especificación", "tags": ["Config"]},
    "GET /api/docs":           {"summary": "Swagger UI", "tags": ["Config"]},
    # ── Escaneos e historial ─────────────────────────────────────────────────
    "GET /api/network/discover": {"summary": "Descubrimiento rápido de dispositivos", "tags": ["Assets"],
                                  "parameters": [{"name": "networks", "in": "query", "description": "CIDRs separados por coma (máx. 5, mínimo /16)"}]},
    "POST /api/scan/runtime":  {"summary": "Análisis en vivo de contenedores", "tags": ["Scans"],
                                "requestBody": {"properties": {"containers": {"type": "array", "items": {"type": "string"}}}}},
    "POST /api/findings/explain": {"summary": "Explicación del hallazgo con el LLM local (Ollama)", "tags": ["Remediation"],
                                   "requestBody": {"required": True, "properties": {"finding_id": {"type": "string"}}}},
    "POST /api/import/audit":  {"summary": "Importar auditoría externa (multipart: file, format, target)", "tags": ["Scans"]},
    "GET /api/import/formats": {"summary": "Formatos de importación admitidos", "tags": ["Scans"]},
    "POST /api/report/{fmt}":  {"summary": "Informe html | ansible | json", "tags": ["Reports"],
                                "parameters": [{"name": "fmt", "in": "path", "required": True}],
                                "requestBody": {"properties": {"source": {"type": "string"}, "findings": {"type": "array"}}}},
    # ── Remediación ──────────────────────────────────────────────────────────
    "GET /api/rollback":       {"summary": "Fixes locales que se pueden deshacer", "tags": ["Remediation"]},
    "POST /api/rollback/local": {"summary": "Deshacer un fix local", "tags": ["Remediation"],
                                 "requestBody": {"required": True, "properties": {"finding_id": {"type": "string"}}}},
    # ── Usuarios ─────────────────────────────────────────────────────────────
    "PATCH /api/users/{username}": {"summary": "Cambiar rol o activar/desactivar", "tags": ["Users"],
                                    "requestBody": {"properties": {"role": {"type": "string", "enum": ["admin", "operator", "viewer"]},
                                                                   "active": {"type": "boolean"}, "password": {"type": "string"}}}},
    "DELETE /api/users/{username}": {"summary": "Desactivar usuario (borrado lógico)", "tags": ["Users"]},
    # ── Scheduler ────────────────────────────────────────────────────────────
    "GET /api/scheduler":      {"summary": "Tareas programadas", "tags": ["Config"]},
    "POST /api/scheduler/{name}/run": {"summary": "Ejecutar una tarea ahora", "tags": ["Config"]},
    "POST /api/scheduler/{name}/toggle": {"summary": "Activar o desactivar una tarea", "tags": ["Config"],
                                          "requestBody": {"properties": {"enabled": {"type": "boolean"}}}},
    "GET /api/schedules":  {"summary": "Análisis programados de la organización", "tags": ["Config"]},
    "POST /api/schedules": {"summary": "Programar un análisis (red, web, TLS, DNS… dentro del ámbito)", "tags": ["Config"],
                            "requestBody": {"properties": {
                                "name": {"type": "string"},
                                "task": {"type": "string", "enum": ["network", "ssh", "web_headers", "web_exposure",
                                                                    "api_security", "nuclei", "tls", "dns",
                                                                    "subdomain_enum"]},
                                "ssh_credential": {"type": "string",
                                                   "description": "Credencial SSH guardada: obligatoria en ssh; "
                                                                  "en network añade la auditoría SSH"},
                                "targets": {"type": "array", "items": {"type": "string"}},
                                "hour": {"type": "integer"}, "minute": {"type": "integer"},
                                "days": {"type": "array", "items": {"type": "integer"},
                                         "description": "0 = lunes … 6 = domingo"},
                                "enabled": {"type": "boolean"}}}},
    "PATCH /api/schedules/{sid}":  {"summary": "Modificar o pausar una programación", "tags": ["Config"]},
    "DELETE /api/schedules/{sid}": {"summary": "Borrar una programación", "tags": ["Config"]},
    "POST /api/schedules/{sid}/run": {"summary": "Lanzar ahora una programación (en segundo plano)", "tags": ["Config"]},
    "GET /api/config/ssh-credentials": {"summary": "Credenciales SSH guardadas (sin el secreto)", "tags": ["Config"]},
    "POST /api/config/ssh-credentials": {
        "summary": "Guardar una credencial SSH (se cifra; generate crea un par ed25519 y devuelve la clave pública)",
        "tags": ["Config"],
        "requestBody": {"properties": {
            "name": {"type": "string"}, "username": {"type": "string"}, "port": {"type": "integer"},
            "kind": {"type": "string", "enum": ["generate", "key", "password"]},
            "private_key": {"type": "string"}, "passphrase": {"type": "string"}, "password": {"type": "string"}}}},
    "PATCH /api/config/ssh-credentials/{cid}": {"summary": "Modificar una credencial SSH", "tags": ["Config"]},
    "GET /api/config/ssh-host-keys": {"summary": "Claves de host SSH guardadas en la primera conexión (TOFU)",
                                      "tags": ["Config"]},
    "DELETE /api/config/ssh-host-keys/{host}/{port}": {
        "summary": "Olvidar la clave de un host (la próxima conexión guarda la que presente)", "tags": ["Config"]},
    "DELETE /api/config/ssh-credentials/{cid}": {"summary": "Borrar una credencial SSH (no si la usa un programado)",
                                                  "tags": ["Config"]},
    # ── Configuración ────────────────────────────────────────────────────────
    "GET /api/config/keys":    {"summary": "API keys configuradas (enmascaradas)", "tags": ["Config"]},
    "POST /api/config/keys":   {"summary": "Guardar API keys (shodan, virustotal, abuseipdb, greynoise, otx, hibp)", "tags": ["Config"]},
    "GET /api/config/notifications":  {"summary": "Configuración de email y webhook", "tags": ["Config"]},
    "POST /api/config/notifications": {"summary": "Guardar email y webhook", "tags": ["Config"]},
    "POST /api/config/notifications/test": {"summary": "Enviar notificación de prueba", "tags": ["Config"]},
    "GET /api/config/siem":    {"summary": "Configuración SIEM", "tags": ["Config"]},
    "POST /api/config/siem":   {"summary": "Guardar configuración SIEM", "tags": ["Config"]},
    "GET /api/config/ticketing":  {"summary": "Configuración de Jira / ServiceNow", "tags": ["Config"]},
    "POST /api/config/ticketing": {"summary": "Guardar Jira / ServiceNow", "tags": ["Config"]},
    "POST /api/config/ticketing/test": {"summary": "Crear ticket de prueba", "tags": ["Config"]},
    "GET /api/config/agent":   {"summary": "Modo agente (standalone | manager | agent)", "tags": ["Agent"]},
    "POST /api/config/agent":  {"summary": "Guardar modo agente", "tags": ["Agent"],
                                "requestBody": {"properties": {"mode": {"type": "string"}, "manager_url": {"type": "string"},
                                                               "agent_key": {"type": "string"}, "agent_name": {"type": "string"}}}},
    "GET /api/quarantine/stats": {"summary": "Estadísticas de la cuarentena", "tags": ["Quarantine"]},
    "GET /api/ansible/templates": {"summary": "Plantillas de AWX/Tower", "tags": ["Ansible"]},
    # ── Intel ────────────────────────────────────────────────────────────────
    "POST /api/intel/scan":    {"summary": "Analizar IPs, dominios o hashes", "tags": ["Intel"],
                                "requestBody": {"properties": {"targets": {"type": "array"}, "from_last_network_scan": {"type": "boolean"}}}},
    "GET /api/intel/lookup":   {"summary": "Consulta rápida de un indicador", "tags": ["Intel"],
                                "parameters": [{"name": "target", "in": "query", "required": True}]},
    "GET /api/intel/history":  {"summary": "Consultas de intel anteriores", "tags": ["Intel"]},
    "GET /api/intel/config":   {"summary": "Fuentes de intel con API key configurada", "tags": ["Intel"]},
    # ── Multi-tenant ─────────────────────────────────────────────────────────
    "GET /api/tenants/{slug}":    {"summary": "Detalle de un tenant", "tags": ["MultiTenant"]},
    "PATCH /api/tenants/{slug}":  {"summary": "Modificar tenant (nombre, email, ámbito de análisis)", "tags": ["MultiTenant"],
                                   "requestBody": {"properties": {
                                       "name": {"type": "string"}, "admin_email": {"type": "string"},
                                       "allowed_targets": {"type": "array", "items": {"type": "string"},
                                                           "description": "Redes CIDR, IPs y dominios que la "
                                                                          "organización puede analizar; vacío = ninguno"}}}},
    "DELETE /api/tenants/{slug}": {"summary": "Dar de baja un tenant (sus datos se archivan)", "tags": ["MultiTenant"]},
    "POST /api/tenants/{slug}/rotate-key": {"summary": "Nueva API key del tenant (la de sus agentes)", "tags": ["MultiTenant"]},
    "GET /api/tenant/agent-key": {"summary": "API key de la organización para sus agentes (su admin)", "tags": ["MultiTenant"]},
    "POST /api/tenant/switch": {"summary": "Superadmin: tenant que muestra la UI", "tags": ["MultiTenant"],
                                "requestBody": {"properties": {"slug": {"type": "string"}}}},
}

TAGS = [
    {"name": "Dashboard",    "description": "Métricas globales y tendencias"},
    {"name": "Scans",        "description": "Historial y comparación de scans"},
    {"name": "Scoring",      "description": "Motor de puntuación contextual"},
    {"name": "Assets",       "description": "Inventario de dispositivos de red"},
    {"name": "Suppressions", "description": "Gestión de falsos positivos"},
    {"name": "Users",        "description": "Gestión de usuarios y roles"},
    {"name": "Remediation",  "description": "Corrección automática de hallazgos"},
    {"name": "Reports",      "description": "Generación de informes PDF y HTML"},
    {"name": "Compliance",   "description": "ENS, ISO 27001, PCI-DSS, CIS Controls"},
    {"name": "SBOM",         "description": "Software Bill of Materials (CycloneDX/SPDX)"},
    {"name": "Quarantine",   "description": "Cuarentena de ficheros maliciosos"},
    {"name": "Auth",         "description": "Autenticación y 2FA TOTP"},
    {"name": "Agent",        "description": "Modo agente multi-servidor"},
    {"name": "Monitor",      "description": "Monitor eBPF/auditd en tiempo real"},
    {"name": "YARA",         "description": "Reglas YARA de detección de malware"},
    {"name": "Config",       "description": "Configuración del servidor"},
    {"name": "WebSocket",    "description": "Canales WebSocket para streaming"},
    {"name": "Ansible",      "description": "Integración Ansible AWX/Tower"},
    {"name": "Intel",        "description": "Threat intelligence (Shodan, VirusTotal, AbuseIPDB…)"},
    {"name": "MultiTenant",  "description": "Modo multi-tenant (SaaS)"},
]


def build_openapi_spec(server_url: str = "https://localhost:8443") -> dict:
    """Construye el spec OpenAPI 3.0 completo."""
    paths: dict[str, Any] = {}

    for key, meta in ENDPOINT_DOCS.items():
        method, path = key.split(" ", 1)
        method_lower = method.lower()

        if path not in paths:
            paths[path] = {}

        operation: dict[str, Any] = {
            "summary":     meta.get("summary", ""),
            "description": meta.get("description", ""),
            "tags":        meta.get("tags", ["Other"]),
            "security":    [{"BearerAuth": []}],
            "responses": meta.get("responses", {
                "200": {"description": "OK"},
                "401": {"description": "No autorizado"},
                "500": {"description": "Error interno"},
            }),
        }

        if "parameters" in meta:
            operation["parameters"] = meta["parameters"]

        if "requestBody" in meta:
            props = meta["requestBody"].get("properties", {})
            required = meta["requestBody"].get("required", False)
            operation["requestBody"] = {
                "required": required,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                k: v if isinstance(v, dict) else {"type": "string"}
                                for k, v in props.items()
                            },
                        }
                    }
                },
            }

        paths[path][method_lower] = operation

    return {
        "openapi": "3.0.3",
        "info": {
            "title":       "CyberHound Pro API",
            "description": (
                "API REST de CyberHound Pro — Plataforma de auditoría y seguridad para PYMEs.\n\n"
                "**Autenticación**: `POST /login` (formulario con `username`, `password` y el `_csrf` "
                "de la cookie `ch_csrf`) devuelve la sesión en la cookie `ch_token`; su valor sirve "
                "también como `Authorization: Bearer <token>`. Desde esta página se usa la sesión del "
                "navegador.\n\n"
                "**WebSocket**: conectar a `/ws` y enviar una tarea, p. ej. `{\"task\": \"audit\"}` "
                "(lista completa en el README).\n\n"
                "**Modo agente**: Los agentes usan `Authorization: AgentKey <key>` en `/api/agent/*`."
            ),
            "version":     __version__,
            "contact": {
                "name":  "CyberHound Pro",
                "url":   "https://github.com/jl-segurayuste/cyberhound-pro",
            },
            "license": {"name": "AGPL-3.0", "url": "https://www.gnu.org/licenses/agpl-3.0.html"},
        },
        "servers": [{"url": server_url, "description": "Servidor CyberHound Pro"}],
        "tags": TAGS,
        "paths": paths,
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type":         "http",
                    "scheme":       "bearer",
                    "bearerFormat": "JWT",
                    "description":  "JWT obtenido en POST /login",
                },
                "AgentKey": {
                    "type":        "apiKey",
                    "in":          "header",
                    "name":        "Authorization",
                    "description": "AgentKey <clave> para endpoints de agentes",
                },
            },
            "schemas": {
                "Finding": {
                    "type": "object",
                    "properties": {
                        "id":          {"type": "string"},
                        "category":    {"type": "string"},
                        "severity":    {"type": "string", "enum": ["critical","high","medium","low","info"]},
                        "title":       {"type": "string"},
                        "description": {"type": "string"},
                        "remediation": {"type": "string"},
                        "evidence":    {"type": "string"},
                        "auto_fix":    {"type": "boolean"},
                        "file_path":   {"type": "string"},
                        "source_host": {"type": "string"},
                    },
                },
                "DashboardStats": {
                    "type": "object",
                    "properties": {
                        "last_scans":          {"type": "object"},
                        "total_assets":        {"type": "integer"},
                        "unauthorized_assets": {"type": "integer"},
                        "score_trend":         {"type": "array"},
                        "critical_findings":   {"type": "array"},
                    },
                },
            },
        },
    }


SWAGGER_UI_HTML = """<!DOCTYPE html>
<html><head>
<title>CyberHound Pro API Docs</title>
<meta charset="utf-8">
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/vendor/swagger-ui/swagger-ui.css">
<style>
  body { margin: 0; background: #0d1117; }
  .swagger-ui .topbar { background: #161b22; border-bottom: 1px solid #30363d; }
  .swagger-ui .topbar .download-url-wrapper { display: none; }
  .swagger-ui .info .title { color: #58a6ff; }
  .swagger-ui { max-width: 1200px; margin: 0 auto; padding: 20px; }
</style>
</head><body>
<div id="swagger-ui"></div>
<script src="/static/vendor/swagger-ui/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: "/api/openapi.json",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: "BaseLayout",
  deepLinking: true,
  tryItOutEnabled: true,
  requestInterceptor: req => {
    const token = document.cookie.match(/ch_token=([^;]+)/)?.[1];
    if (token) req.headers['Authorization'] = 'Bearer ' + token;
    return req;
  },
});
</script>
</body></html>"""
