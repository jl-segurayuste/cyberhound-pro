"""
Documentación OpenAPI 3.0 para CyberHound Pro.

Genera automáticamente el spec OpenAPI a partir de las rutas registradas
en aiohttp y metadatos adicionales decoradores/dicts por endpoint.

El spec se sirve en /api/openapi.json y la UI en /api/docs (Swagger UI).
"""
from __future__ import annotations

from typing import Any

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
    "GET /api/history/{id}": {
        "summary": "Findings de un scan",
        "tags": ["Scans"],
        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
    },
    "GET /api/history/{id}/compare": {
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
                "finding_id_pattern": {"type": "string", "description": "Patrón glob (e.g. ssh_*)"},
                "reason": {"type": "string"},
                "expires_at": {"type": "string", "format": "date-time"},
            },
        },
    },
    "DELETE /api/suppressions/{id}": {
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
                "role": {"type": "string", "enum": ["admin", "analyst", "viewer"]},
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
    "GET /api/license": {"summary": "Información de licencia", "tags": ["License"]},
    "POST /api/license/activate": {
        "summary": "Activar licencia",
        "tags": ["License"],
        "requestBody": {
            "required": True,
            "properties": {"key": {"type": "string"}},
        },
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
        "description": "Conectar para lanzar y monitorear scans en tiempo real. "
                       "Enviar {task: 'audit'|'malware'|'network'|'ssh'|'docker'|'code'|'intel'|'services'}",
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
    "POST /api/tenants":       {"summary": "Crear tenant", "tags": ["MultiTenant"]},
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
    {"name": "License",      "description": "Gestión de licencias"},
    {"name": "Auth",         "description": "Autenticación y 2FA TOTP"},
    {"name": "Agent",        "description": "Modo agente multi-servidor"},
    {"name": "Monitor",      "description": "Monitor eBPF/auditd en tiempo real"},
    {"name": "YARA",         "description": "Reglas YARA de detección de malware"},
    {"name": "Config",       "description": "Configuración del servidor"},
    {"name": "WebSocket",    "description": "Canales WebSocket para streaming"},
    {"name": "Ansible",      "description": "Integración Ansible AWX/Tower"},
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
                "**Autenticación**: JWT Bearer en cabecera `Authorization: Bearer <token>` "
                "obtenido en `POST /login`.\n\n"
                "**WebSocket**: Conectar a `/ws` para lanzar scans en tiempo real. "
                "Enviar `{\"task\": \"audit\"}` para iniciar.\n\n"
                "**Modo agente**: Los agentes usan `Authorization: AgentKey <key>` en `/api/agent/*`."
            ),
            "version":     "6.2.0",
            "contact": {
                "name":  "CyberHound Pro",
                "url":   "https://github.com/jl-segurayuste/cyberhound-pro",
                "email": "security@cyberhound.local",
            },
            "license": {"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
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
