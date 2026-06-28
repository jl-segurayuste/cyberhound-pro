"""
Módulo de seguridad de CyberHound.

Implementa:
  1. RateLimiter    — límite de intentos por IP con bloqueo temporal
  2. InputValidator — sanitización de todos los inputs de la API
  3. CsrfProtection — tokens CSRF para formularios POST
  4. TLSManager     — generación automática de certificados auto-firmados
                      y soporte de Let's Encrypt via certbot

Principios:
  - Fail closed: ante la duda, denegar
  - Los bloqueos se loguean siempre con IP y motivo
  - Los errores de validación devuelven 400, no 500
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path

from aiohttp import web

from cyberhound.core.logging import audit_log, get_logger

logger = get_logger("security")


# ──────────────────────────────────────────────────────────────────────────────
# 1. RATE LIMITER
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RateLimitEntry:
    attempts:     int   = 0
    blocked_until: float = 0.0   # timestamp unix
    first_attempt: float = field(default_factory=time.monotonic)


class RateLimiter:
    """
    Rate limiting por IP con bloqueo exponencial.

    Política por defecto para /login:
      - 5 intentos fallidos en 15 minutos → bloqueo de 15 minutos
      - 10 intentos en total → bloqueo de 1 hora
      - 20 intentos → bloqueo de 24 horas

    Los bloqueos son en memoria (se resetean al reiniciar).
    Para producción seria usar Redis, pero para on-premise esto es suficiente.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 900,    # 15 minutos
        block_seconds: int = 900,     # bloqueo inicial: 15 min
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._store: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = asyncio.Lock()
        # IPs en lista blanca (nunca bloqueadas)
        self._whitelist: set[str] = {"127.0.0.1", "::1"}

    def add_whitelist(self, ip: str) -> None:
        self._whitelist.add(ip)

    async def is_allowed(self, ip: str) -> tuple[bool, int]:
        """
        Comprueba si la IP puede hacer una petición.
        Devuelve (permitido, segundos_de_espera).
        """
        if ip in self._whitelist:
            return True, 0

        async with self._lock:
            entry = self._store[ip]
            now = time.monotonic()

            # Comprobar si está bloqueada
            if entry.blocked_until > now:
                wait = int(entry.blocked_until - now)
                return False, wait

            # Limpiar ventana expirada
            if now - entry.first_attempt > self.window_seconds:
                self._store[ip] = RateLimitEntry()
                return True, 0

            return True, 0

    async def record_failure(self, ip: str) -> tuple[bool, int]:
        """
        Registra un intento fallido.
        Devuelve (bloqueado_ahora, segundos_bloqueo).
        """
        if ip in self._whitelist:
            return False, 0

        async with self._lock:
            entry = self._store[ip]
            entry.attempts += 1
            now = time.monotonic()

            # Calcular bloqueo exponencial
            if entry.attempts >= 20:
                block = 86400  # 24 horas
            elif entry.attempts >= 10:
                block = 3600   # 1 hora
            elif entry.attempts >= self.max_attempts:
                block = self.block_seconds  # 15 min por defecto
            else:
                return False, 0

            entry.blocked_until = now + block
            logger.warning(
                "IP bloqueada por rate limit: %s (%d intentos, bloqueo %ds)",
                ip, entry.attempts, block,
            )
            audit_log.auth_failure(ip, f"rate_limit blocked ({entry.attempts} attempts, {block}s)")
            return True, block

    async def record_success(self, ip: str) -> None:
        """Resetea el contador tras login exitoso."""
        async with self._lock:
            if ip in self._store:
                del self._store[ip]

    async def cleanup_expired(self) -> None:
        """Limpia entradas expiradas (llamar periódicamente)."""
        async with self._lock:
            now = time.monotonic()
            expired = [
                ip for ip, entry in self._store.items()
                if entry.blocked_until < now
                and now - entry.first_attempt > self.window_seconds
            ]
            for ip in expired:
                del self._store[ip]
            if expired:
                logger.debug("Rate limiter: %d entradas expiradas eliminadas", len(expired))

    def middleware_factory(self, protected_paths: set[str]):
        """
        Devuelve un middleware aiohttp que aplica rate limiting
        a las rutas especificadas.
        """
        limiter = self

        @web.middleware
        async def rate_limit_middleware(request: web.Request, handler):
            if request.path not in protected_paths:
                return await handler(request)

            ip = _get_real_ip(request)
            allowed, wait = await limiter.is_allowed(ip)
            if not allowed:
                logger.warning("Rate limit: petición bloqueada de %s (espera %ds)", ip, wait)
                raise web.HTTPTooManyRequests(
                    reason=f"Demasiados intentos. Espera {wait} segundos.",
                    headers={"Retry-After": str(wait)},
                )
            return await handler(request)

        return rate_limit_middleware


def _get_real_ip(request: web.Request) -> str:
    """
    Obtiene la IP real del cliente.
    Considera cabeceras de proxy (X-Forwarded-For, X-Real-IP)
    solo si vienen de localhost (proxy de confianza).
    """
    peer = request.transport and request.transport.get_extra_info("peername")
    peer_ip = peer[0] if peer else "unknown"

    # Solo confiar en cabeceras de proxy si la petición viene de localhost
    if peer_ip in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")
        if forwarded and forwarded[0].strip():
            candidate = forwarded[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
        real_ip = request.headers.get("X-Real-IP", "").strip()
        if real_ip:
            try:
                ipaddress.ip_address(real_ip)
                return real_ip
            except ValueError:
                pass

    return peer_ip


# ──────────────────────────────────────────────────────────────────────────────
# 2. VALIDACIÓN DE INPUTS
# ──────────────────────────────────────────────────────────────────────────────

class ValidationError(Exception):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"{field}: {reason}")


class InputValidator:
    """
    Sanitiza y valida todos los inputs que llegan por WebSocket o REST.
    Fail closed: si algo no pasa la validación, lanza ValidationError.
    """

    # Caracteres permitidos en rutas de fichero
    _PATH_SAFE = re.compile(r'^[a-zA-Z0-9/_\-. ~]+$')
    # IPs válidas (IPv4 o hostname simple)
    _IP_RE = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'          # IPv4
        r'|^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'  # hostname
    )
    # CIDR válido
    _CIDR_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')

    @staticmethod
    def path(value: str, field_name: str = "path") -> str:
        """Valida una ruta de sistema de ficheros."""
        if not value or not isinstance(value, str):
            raise ValidationError(field_name, "Ruta vacía o inválida")
        value = value.strip()
        if len(value) > 512:
            raise ValidationError(field_name, "Ruta demasiado larga")
        # Normalizar para detectar path traversal
        try:
            normalized = str(Path(value).resolve())
        except Exception:
            raise ValidationError(field_name, "Ruta no normalizable") from None
        # Bloquear path traversal explícito
        if ".." in value:
            raise ValidationError(field_name, "Path traversal no permitido")
        # Solo caracteres seguros
        if not InputValidator._PATH_SAFE.match(value):
            raise ValidationError(field_name, f"Caracteres no permitidos en ruta: {value}")
        # Debe ser ruta absoluta
        if not value.startswith("/"):
            raise ValidationError(field_name, "Se requiere ruta absoluta")
        return normalized

    @staticmethod
    def ip_or_hostname(value: str, field_name: str = "host") -> str:
        """Valida una IP o hostname."""
        if not value or not isinstance(value, str):
            raise ValidationError(field_name, "IP/hostname vacío")
        value = value.strip()
        if len(value) > 253:
            raise ValidationError(field_name, "Hostname demasiado largo")
        # Verificar si parece una IP (contiene solo dígitos y puntos)
        # y en ese caso forzar la validación estricta como IP
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
            try:
                ipaddress.ip_address(value)
                return value
            except ValueError:
                raise ValidationError(field_name, f"Dirección IPv4 inválida: {value}") from None
        # Intentar como IPv6 o IP genérica
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        # Verificar hostname válido (RFC 1123)
        hostname_re = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        if not hostname_re.match(value):
            raise ValidationError(field_name, f"IP/hostname inválido: {value}")
        return value

    @staticmethod
    def host_list(value: str, field_name: str = "hosts", max_hosts: int = 50) -> list[str]:
        """Valida una lista de IPs/hostnames separados por coma, espacio o línea."""
        if not value:
            raise ValidationError(field_name, "Lista de hosts vacía")
        raw = re.split(r'[,\s\n]+', value.strip())
        hosts = [h.strip() for h in raw if h.strip()]
        if not hosts:
            raise ValidationError(field_name, "Sin hosts válidos")
        if len(hosts) > max_hosts:
            raise ValidationError(field_name, f"Máximo {max_hosts} hosts por escaneo")
        return [InputValidator.ip_or_hostname(h, field_name) for h in hosts]

    @staticmethod
    def network_cidr(value: str, field_name: str = "network") -> str:
        """Valida una red en formato CIDR."""
        if not value:
            return value
        value = value.strip()
        if not InputValidator._CIDR_RE.match(value):
            raise ValidationError(field_name, f"CIDR inválido: {value}")
        # Verificar que la red es válida
        try:
            net = ipaddress.ip_network(value, strict=False)
            # Bloquear redes demasiado grandes (/8 o mayores)
            if net.prefixlen < 16:
                raise ValidationError(field_name, f"Red demasiado grande (/{net.prefixlen}). Mínimo /16")
        except ValueError as e:
            raise ValidationError(field_name, str(e)) from e
        return value

    @staticmethod
    def network_list(value: str, max_networks: int = 5) -> list[str]:
        """Valida una lista de redes CIDR."""
        if not value:
            return []
        parts = [p.strip() for p in value.split(",") if p.strip()]
        if len(parts) > max_networks:
            raise ValidationError("networks", f"Máximo {max_networks} redes")
        return [InputValidator.network_cidr(p) for p in parts]

    @staticmethod
    def port(value, field_name: str = "port") -> int:
        """Valida un número de puerto."""
        try:
            p = int(value)
        except (TypeError, ValueError):
            raise ValidationError(field_name, "Puerto debe ser un número") from None
        if not 1 <= p <= 65535:
            raise ValidationError(field_name, f"Puerto fuera de rango: {p}")
        return p

    @staticmethod
    def ssh_username(value: str) -> str:
        """Valida un nombre de usuario SSH."""
        if not value:
            return "root"
        value = value.strip()
        if not re.match(r'^[a-zA-Z0-9_\-]{1,32}$', value):
            raise ValidationError("ssh_user", f"Usuario SSH inválido: {value}")
        return value

    @staticmethod
    def modules_list(value: list, allowed: set, field_name: str = "modules") -> list[str]:
        """Valida una lista de módulos contra un conjunto permitido."""
        if not isinstance(value, list):
            raise ValidationError(field_name, "Debe ser una lista")
        invalid = [m for m in value if m not in allowed]
        if invalid:
            raise ValidationError(field_name, f"Módulos no permitidos: {invalid}")
        return [str(m) for m in value]

    @staticmethod
    def url_list(value, field_name: str = "urls", max_items: int = 50) -> list[str]:
        """Valida una lista de URLs/hosts/dominios.

        Acepta una lista o una cadena separada por comas/saltos de línea.
        Rechaza espacios y metacaracteres peligrosos (anti-inyección), de modo
        que sea seguro pasar los valores a clientes HTTP o a binarios externos.
        """
        if isinstance(value, str):
            items = re.split(r"[\n,]", value)
        elif isinstance(value, list):
            items = [str(v) for v in value]
        else:
            raise ValidationError(field_name, "Debe ser una lista de URLs")
        items = [i.strip() for i in items if i and i.strip()]
        if len(items) > max_items:
            raise ValidationError(field_name, f"Máximo {max_items} objetivos")
        pattern = re.compile(r"^(https?://)?[A-Za-z0-9._~:/?#@%+=&\[\]-]+$")
        out = []
        for it in items:
            if len(it) > 2048 or not pattern.match(it):
                raise ValidationError(field_name, f"URL/dominio inválido: {it[:60]}")
            out.append(it)
        return out

    @staticmethod
    def ws_message(msg: dict) -> dict:
        """
        Valida y sanitiza un mensaje WebSocket completo.
        Lanza ValidationError si algo no es válido.
        Devuelve el mensaje sanitizado.
        """
        ALLOWED_TASKS = {
            "audit", "malware", "network", "ssh", "code", "intel", "docker", "services",
            "tls", "web_headers", "dns", "web_exposure", "api_security",
            "subdomain_enum", "nuclei",
        }
        ALLOWED_MALWARE_MODULES = {"yara", "hash", "auditd", "cron", "webshell"}
        ALLOWED_INTEL_MODULES = {"shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp"}

        task = msg.get("task", "")
        if task not in ALLOWED_TASKS:
            raise ValidationError("task", f"Tarea no permitida: {task}")

        sanitized: dict = {"task": task}

        if task == "code":
            sanitized["path"] = InputValidator.path(msg.get("path", ""), "path")

        elif task == "malware":
            skip = msg.get("skip", [])
            sanitized["skip"] = InputValidator.modules_list(skip, ALLOWED_MALWARE_MODULES, "skip")
            # Ruta de reglas YARA (opcional)
            yr = msg.get("yara_rules")
            if yr:
                sanitized["yara_rules"] = InputValidator.path(yr, "yara_rules")
            # Rutas YARA extra (opcional)
            yp = msg.get("yara_paths")
            if yp and isinstance(yp, list):
                sanitized["yara_paths"] = [InputValidator.path(p, "yara_paths") for p in yp[:5]]
            # Web roots (opcional)
            wr = msg.get("web_roots")
            if wr and isinstance(wr, list):
                sanitized["web_roots"] = [InputValidator.path(p, "web_roots") for p in wr[:5]]

        elif task in ("ssh", "network"):
            if task == "network":
                networks_raw = msg.get("networks", "")
                sanitized["networks"] = ",".join(InputValidator.network_list(networks_raw))
            else:
                sanitized["hosts"] = " ".join(
                    InputValidator.host_list(msg.get("hosts", ""), "hosts")
                )
            sanitized["ssh_user"] = InputValidator.ssh_username(msg.get("ssh_user", "root"))
            sanitized["ssh_port"] = InputValidator.port(msg.get("ssh_port", 22), "ssh_port")
            # Clave SSH: ruta opcional
            key = msg.get("ssh_key", "")
            if key:
                sanitized["ssh_key"] = InputValidator.path(key, "ssh_key")
            # Contraseña: solo en memoria, nunca se loguea
            if msg.get("ssh_password"):
                sanitized["ssh_password"] = str(msg["ssh_password"])
            sanitized["ssh_audit"] = bool(msg.get("ssh_audit", True))
            sanitized["vuln_scan"] = bool(msg.get("vuln_scan", False))

        if task == "docker":
            sanitized["scan_images_cve"] = bool(msg.get("scan_images_cve", True))
            sanitized["scan_k8s"]        = bool(msg.get("scan_k8s", True))

        elif task == "intel":
            sanitized["target"] = InputValidator.ip_or_hostname(
                msg.get("target", ""), "target"
            )
            modules = msg.get("modules", [])
            sanitized["modules"] = InputValidator.modules_list(
                modules, ALLOWED_INTEL_MODULES, "modules"
            )

        elif task in ("web_exposure", "api_security", "web_headers", "nuclei"):
            sanitized["urls"] = InputValidator.url_list(msg.get("urls", []), "urls")
            if task == "nuclei":
                sev = msg.get("severities") or []
                if sev:
                    sanitized["severities"] = InputValidator.modules_list(
                        sev, {"info", "low", "medium", "high", "critical"}, "severities"
                    )

        elif task in ("subdomain_enum", "dns"):
            sanitized["domains"] = InputValidator.url_list(msg.get("domains", []), "domains")

        elif task == "tls":
            sanitized["targets"] = InputValidator.url_list(msg.get("targets", []), "targets")

        return sanitized


# ──────────────────────────────────────────────────────────────────────────────
# 3. CSRF PROTECTION
# ──────────────────────────────────────────────────────────────────────────────

class CsrfProtection:
    """
    Protección CSRF para formularios POST.
    Usa el patrón Double Submit Cookie:
      1. Genera un token aleatorio por sesión
      2. Lo incluye en el formulario como campo oculto (_csrf)
      3. En cada POST del formulario verifica que cookie == campo

    RUTAS EXENTAS:
      - /login:  gestiona su propio token (lo verifica en login_post)
      - /logout: GET
      - /api/*:  autenticadas con JWT, no necesitan CSRF
      - /ws:     WebSocket, no aplica
    """

    COOKIE_NAME = "ch_csrf"
    FIELD_NAME  = "_csrf"

    @staticmethod
    def generate_token() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def get_or_create_token(request: web.Request) -> str:
        return request.cookies.get(CsrfProtection.COOKIE_NAME) or CsrfProtection.generate_token()

    @staticmethod
    def inject_token(response: web.Response, token: str, is_https: bool = True) -> None:
        """Inyecta la cookie CSRF. Siempre Secure=True cuando hay HTTPS."""
        response.set_cookie(
            CsrfProtection.COOKIE_NAME, token,
            httponly=False,        # JS necesita leerla para formularios dinámicos
            samesite="Strict",
            secure=is_https,       # True en producción (HTTPS), False solo en dev HTTP
            max_age=3600,
        )

    def middleware_factory(self, is_https: bool = True):
        csrf = self

        @web.middleware
        async def csrf_middleware(request: web.Request, handler):
            # Solo verificar métodos que modifican estado
            if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
                return await handler(request)

            # Exentar WebSocket upgrades
            if request.headers.get("Upgrade", "").lower() == "websocket":
                return await handler(request)

            # Exentar /login y /logout (gestionan su propio token)
            if request.path in ("/login", "/logout"):
                return await handler(request)

            # Exentar todas las rutas /api/* (autenticadas con JWT Bearer)
            if request.path.startswith("/api/"):
                return await handler(request)

            # Para cualquier otro POST de formulario: verificar double-submit
            cookie_token = request.cookies.get(csrf.COOKIE_NAME)
            if not cookie_token:
                logger.warning(
                    "CSRF: cookie '%s' ausente en POST %s desde %s",
                    csrf.COOKIE_NAME, request.path, _get_real_ip(request),
                )
                raise web.HTTPForbidden(reason="CSRF token requerido")

            try:
                data = await request.post()
                form_token = data.get(csrf.FIELD_NAME, "")
            except Exception:
                form_token = ""

            if not form_token or not secrets.compare_digest(cookie_token, form_token):
                logger.warning(
                    "CSRF: token inválido en POST %s desde %s",
                    request.path, _get_real_ip(request),
                )
                audit_log.auth_failure(
                    _get_real_ip(request), f"CSRF mismatch en {request.path}"
                )
                raise web.HTTPForbidden(reason="CSRF token inválido")

            return await handler(request)

        return csrf_middleware


# ──────────────────────────────────────────────────────────────────────────────
# 4. TLS MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class TLSManager:
    """
    Gestión de certificados TLS.

    Modos:
      1. auto-signed: genera un certificado auto-firmado en el primer arranque
         → para uso en red local / desarrollo
      2. certbot: usa Let's Encrypt para un dominio público
         → para exposición en internet

    Los certificados auto-firmados se regeneran si están a menos de 30 días
    de expirar.
    """

    CERT_DIR = Path("/etc/cyberhound/tls")
    CERT_FILE = CERT_DIR / "cert.pem"
    KEY_FILE  = CERT_DIR / "key.pem"
    # Fallback en home si no hay permisos en /etc
    CERT_DIR_HOME = Path.home() / ".cyberhound" / "tls"

    @classmethod
    def get_cert_dir(cls) -> Path:
        try:
            cls.CERT_DIR.mkdir(parents=True, exist_ok=True)
            test = cls.CERT_DIR / ".write_test"
            test.touch()
            test.unlink()
            return cls.CERT_DIR
        except PermissionError:
            cls.CERT_DIR_HOME.mkdir(parents=True, exist_ok=True)
            return cls.CERT_DIR_HOME

    @classmethod
    def cert_paths(cls) -> tuple[Path, Path]:
        d = cls.get_cert_dir()
        return d / "cert.pem", d / "key.pem"

    @classmethod
    def needs_generation(cls) -> bool:
        cert_path, key_path = cls.cert_paths()
        if not cert_path.exists() or not key_path.exists():
            return True
        # Verificar expiración (regenerar si quedan menos de 30 días)
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_pem_x509_certificate(
                cert_path.read_bytes(), default_backend()
            )
            from datetime import datetime
            remaining = cert.not_valid_after_utc - datetime.now(UTC)
            if remaining.days < 30:
                logger.info("Certificado TLS expira en %d días, regenerando", remaining.days)
                return True
            return False
        except Exception as e:
            logger.warning("Error verificando certificado: %s — regenerando", e)
            return True

    @classmethod
    def generate_self_signed(
        cls,
        common_name: str = "cyberhound.local",
        san_ips: list[str] | None = None,
        days: int = 365,
    ) -> tuple[Path, Path]:
        """
        Genera un certificado auto-firmado con:
        - RSA 4096 bits
        - SAN para IPs locales y localhost
        - Válido por 1 año
        """
        try:
            import ipaddress as _ip
            from datetime import datetime, timedelta

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError as e:
            raise RuntimeError(
                "La librería 'cryptography' es necesaria para TLS automático. "
                "Instala con: pip install cryptography"
            ) from e

        cert_path, key_path = cls.cert_paths()
        logger.info("Generando certificado TLS auto-firmado en %s…", cert_path.parent)

        # Generar clave privada RSA 4096
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        # Construir Subject Alternative Names
        san_list: list = [
            x509.DNSName("localhost"),
            x509.DNSName(common_name),
            x509.IPAddress(_ip.IPv4Address("127.0.0.1")),
        ]
        # Añadir IPs locales detectadas
        extra_ips = san_ips or []
        for ip_str in extra_ips:
            try:
                san_list.append(x509.IPAddress(_ip.ip_address(ip_str)))
            except ValueError:
                pass

        # Intentar detectar IPs locales automáticamente
        try:
            import socket
            hostname = socket.gethostname()
            san_list.append(x509.DNSName(hostname))
            local_ip = socket.gethostbyname(hostname)
            san_list.append(x509.IPAddress(_ip.IPv4Address(local_ip)))
        except Exception:
            pass

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberHound Pro"),
        ])

        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Guardar clave privada (permisos 600)
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)

        # Guardar certificado
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        cert_path.chmod(0o644)

        logger.info(
            "✓ Certificado TLS generado: %s (válido %d días, SANs: %d)",
            cert_path, days, len(san_list),
        )
        return cert_path, key_path

    @classmethod
    def ensure_tls(
        cls,
        cert_path: str | None = None,
        key_path: str | None = None,
    ) -> tuple[Path, Path]:
        """
        Asegura que hay certificados TLS disponibles.
        Si se proporcionan rutas, las usa. Si no, auto-genera.
        """
        if cert_path and key_path:
            cp, kp = Path(cert_path), Path(key_path)
            if not cp.exists():
                raise FileNotFoundError(f"Certificado TLS no encontrado: {cp}")
            if not kp.exists():
                raise FileNotFoundError(f"Clave TLS no encontrada: {kp}")
            logger.info("TLS: usando certificados proporcionados: %s", cp)
            return cp, kp

        # Auto-generar si es necesario
        if cls.needs_generation():
            return cls.generate_self_signed()

        return cls.cert_paths()

    @classmethod
    def create_ssl_context(
        cls,
        cert_path: str | None = None,
        key_path: str | None = None,
    ):
        """Crea y devuelve un ssl.SSLContext configurado de forma segura."""
        import ssl
        cp, kp = cls.ensure_tls(cert_path, key_path)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cp), str(kp))
        # Deshabilitar protocolos obsoletos
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Cifrados seguros únicamente
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
            ":!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
        )
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_SINGLE_DH_USE
        ctx.options |= ssl.OP_SINGLE_ECDH_USE
        logger.info("SSL context creado con TLS 1.2+ y cifrados modernos")
        return ctx

    @classmethod
    def setup_lets_encrypt(cls, domain: str, email: str) -> tuple[Path, Path]:
        """
        Configura Let's Encrypt via certbot.
        Requiere que el dominio apunte a esta máquina y el puerto 80 accesible.
        """
        import shutil
        if not shutil.which("certbot"):
            raise RuntimeError(
                "certbot no está instalado. "
                "Instala con: sudo apt install certbot"
            )
        import subprocess
        logger.info("Solicitando certificado Let's Encrypt para %s…", domain)
        result = subprocess.run([
            "certbot", "certonly", "--standalone",
            "--non-interactive", "--agree-tos",
            "--email", email,
            "--domain", domain,
        ], capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"certbot falló: {result.stderr}")

        cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        key  = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
        if not cert.exists():
            raise RuntimeError(f"Certificado no generado en {cert}")

        logger.info("✓ Certificado Let's Encrypt obtenido para %s", domain)
        return cert, key
