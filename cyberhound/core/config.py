"""
Configuración centralizada de CyberHound.
Fuentes (orden de precedencia): variables de entorno > config.yaml > defaults.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from cyberhound.core.logging import get_logger

logger = get_logger("config")

DEFAULT_CONFIG_PATH = Path.home() / ".cyberhound" / "config.yaml"
DEFAULT_DB_PATH     = Path.home() / ".cyberhound" / "cyberhound.db"


@dataclass
class APIKeys:
    shodan:     Optional[str] = None
    virustotal: Optional[str] = None
    abuseipdb:  Optional[str] = None
    greynoise:  Optional[str] = None
    otx:        Optional[str] = None
    hibp:       Optional[str] = None


@dataclass
class AuthSettings:
    mode:            str  = "jwt"
    username:        str  = "admin"
    password_hash:   Optional[str] = None
    secret:          Optional[str] = None
    token_ttl_hours: int  = 8
    localhost_only:  bool = False


@dataclass
class ScanSettings:
    ssh_default_user: str  = "root"
    ssh_default_port: int  = 22
    ssh_key_path:     Optional[str] = None
    nmap_timeout:     int  = 120
    ssh_concurrency:  int  = 5
    max_ww_files:     int  = 200
    hash_scan_max:    int  = 50


@dataclass
class ServerSettings:
    host:     str  = "0.0.0.0"
    port:     int  = 8443
    tls_cert: Optional[str] = None
    tls_key:  Optional[str] = None
    log_dir:  str  = "/var/log/cyberhound"


@dataclass
class SIEMSettings:
    wazuh_enabled:    bool = False
    wazuh_host:       str  = "localhost"
    wazuh_port:       int  = 1514
    wazuh_api_url:    str  = ""
    wazuh_api_user:   str  = ""
    wazuh_api_pass:   str  = ""
    elk_enabled:      bool = False
    elk_url:          str  = "http://localhost:9200"
    elk_index:        str  = "cyberhound-findings"
    elk_user:         str  = ""
    elk_pass:         str  = ""
    elk_api_key:      str  = ""
    splunk_enabled:   bool = False
    splunk_hec_url:   str  = "https://localhost:8088/services/collector"
    splunk_hec_token: str  = ""
    splunk_index:     str  = "cyberhound"
    min_severity:     str  = "medium"


@dataclass
class SchedulerSettings:
    enabled:         bool = True
    audit_enabled:   bool = True
    audit_hour:      int  = 2
    audit_minute:    int  = 0
    malware_enabled: bool = True
    malware_hour:    int  = 3
    malware_minute:  int  = 0
    malware_day:     int  = 0    # 0=lunes
    network_enabled: bool = True
    network_hour:    int  = 4
    network_minute:  int  = 0


@dataclass
class NotificationSettings:
    email_enabled:   bool  = False
    smtp_host:       str   = "smtp.gmail.com"
    smtp_port:       int   = 587
    smtp_user:       str   = ""
    smtp_password:   str   = ""
    email_from:      str   = ""
    email_to:        list  = field(default_factory=list)
    webhook_enabled: bool  = False
    webhook_url:     str   = ""
    min_level:       str   = "warning"


@dataclass
class AgentSettings:
    mode:               str        = "standalone"   # standalone | agent | manager
    manager_url:        str        = ""
    agent_key:          str        = ""
    agent_name:         str        = ""
    registered_agents:  list       = None

    def __post_init__(self):
        if self.registered_agents is None:
            self.registered_agents = []



@dataclass
class CyberHoundConfig:
    api_keys:      APIKeys              = field(default_factory=APIKeys)
    auth:          AuthSettings         = field(default_factory=AuthSettings)
    scan:          ScanSettings         = field(default_factory=ScanSettings)
    server:        ServerSettings       = field(default_factory=ServerSettings)
    scheduler:     SchedulerSettings    = field(default_factory=SchedulerSettings)
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    siem:          SIEMSettings         = field(default_factory=SIEMSettings)
    agent:         AgentSettings        = field(default_factory=AgentSettings)
    db_path:       str = field(default_factory=lambda: str(DEFAULT_DB_PATH))

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "CyberHoundConfig":
        cfg = cls()
        raw: dict = {}
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                logger.info("Configuración cargada desde %s", path)
            except Exception as e:
                logger.error("Error leyendo config %s: %s", path, e)

        # API keys
        kr = raw.get("api_keys", {})
        cfg.api_keys = APIKeys(
            shodan=kr.get("shodan"), virustotal=kr.get("virustotal"),
            abuseipdb=kr.get("abuseipdb"), greynoise=kr.get("greynoise"),
            otx=kr.get("otx"), hibp=kr.get("hibp"),
        )
        for env, attr in [
            ("SHODAN_API_KEY","shodan"), ("VT_API_KEY","virustotal"),
            ("ABUSEIPDB_KEY","abuseipdb"), ("GREYNOISE_KEY","greynoise"),
            ("OTX_KEY","otx"), ("HIBP_API_KEY","hibp"),
        ]:
            if v := os.environ.get(env):
                setattr(cfg.api_keys, attr, v)

        # Auth
        ar = raw.get("auth", {})
        cfg.auth = AuthSettings(
            mode=ar.get("mode", "jwt"),
            username=ar.get("username", "admin"),
            password_hash=ar.get("password_hash"),
            secret=ar.get("secret") or os.environ.get("CH_SECRET"),
            token_ttl_hours=ar.get("token_ttl_hours", 8),
            localhost_only=ar.get("localhost_only", False),
        )

        # Scan
        sr = raw.get("scan", {})
        cfg.scan = ScanSettings(
            ssh_default_user=sr.get("ssh_default_user", "root"),
            ssh_default_port=sr.get("ssh_default_port", 22),
            ssh_key_path=sr.get("ssh_key_path"),
            nmap_timeout=sr.get("nmap_timeout", 120),
            ssh_concurrency=sr.get("ssh_concurrency", 5),
            max_ww_files=sr.get("max_ww_files", 200),
            hash_scan_max=sr.get("hash_scan_max", 50),
        )

        # Server
        svr = raw.get("server", {})
        cfg.server = ServerSettings(
            host=svr.get("host", "0.0.0.0"),
            port=int(svr.get("port", 8443)),
            tls_cert=svr.get("tls_cert"),
            tls_key=svr.get("tls_key"),
            log_dir=svr.get("log_dir", "/var/log/cyberhound"),
        )

        # Scheduler
        schr = raw.get("scheduler", {})
        cfg.scheduler = SchedulerSettings(
            enabled=schr.get("enabled", True),
            audit_enabled=schr.get("audit_enabled", True),
            audit_hour=schr.get("audit_hour", 2),
            audit_minute=schr.get("audit_minute", 0),
            malware_enabled=schr.get("malware_enabled", True),
            malware_hour=schr.get("malware_hour", 3),
            malware_minute=schr.get("malware_minute", 0),
            malware_day=schr.get("malware_day", 0),
            network_enabled=schr.get("network_enabled", True),
            network_hour=schr.get("network_hour", 4),
            network_minute=schr.get("network_minute", 0),
        )

        # Notifications
        nr = raw.get("notifications", {})
        cfg.notifications = NotificationSettings(
            email_enabled=nr.get("email_enabled", False),
            smtp_host=nr.get("smtp_host", "smtp.gmail.com"),
            smtp_port=nr.get("smtp_port", 587),
            smtp_user=nr.get("smtp_user", ""),
            smtp_password=nr.get("smtp_password", os.environ.get("CH_SMTP_PASSWORD", "")),
            email_from=nr.get("email_from", ""),
            email_to=nr.get("email_to", []),
            webhook_enabled=nr.get("webhook_enabled", False),
            webhook_url=nr.get("webhook_url", os.environ.get("CH_WEBHOOK_URL", "")),
            min_level=nr.get("min_level", "warning"),
        )

        cfg.db_path = raw.get("db_path", str(DEFAULT_DB_PATH))

        # SIEM
        sr = raw.get("siem", {})
        cfg.siem = SIEMSettings(
            wazuh_enabled=sr.get("wazuh_enabled", False),
            wazuh_host=sr.get("wazuh_host", "localhost"),
            wazuh_port=sr.get("wazuh_port", 1514),
            wazuh_api_url=sr.get("wazuh_api_url", ""),
            wazuh_api_user=sr.get("wazuh_api_user", ""),
            wazuh_api_pass=sr.get("wazuh_api_pass", os.environ.get("CH_WAZUH_PASS", "")),
            elk_enabled=sr.get("elk_enabled", False),
            elk_url=sr.get("elk_url", "http://localhost:9200"),
            elk_index=sr.get("elk_index", "cyberhound-findings"),
            elk_user=sr.get("elk_user", ""),
            elk_pass=sr.get("elk_pass", os.environ.get("CH_ELK_PASS", "")),
            elk_api_key=sr.get("elk_api_key", os.environ.get("CH_ELK_API_KEY", "")),
            splunk_enabled=sr.get("splunk_enabled", False),
            splunk_hec_url=sr.get("splunk_hec_url", "https://localhost:8088/services/collector"),
            splunk_hec_token=sr.get("splunk_hec_token", os.environ.get("CH_SPLUNK_TOKEN", "")),
            splunk_index=sr.get("splunk_index", "cyberhound"),
            min_severity=sr.get("min_severity", "medium"),
        )

        # Agent settings
        ag = raw.get("agent", {})
        import os as _os
        cfg.agent = AgentSettings(
            mode=ag.get("mode", "standalone"),
            manager_url=ag.get("manager_url", ""),
            agent_key=ag.get("agent_key", _os.environ.get("CH_AGENT_KEY", "")),
            agent_name=ag.get("agent_name", ""),
        )

        return cfg

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not self.auth.secret:
            self.auth.secret = secrets.token_hex(32)
        data = {
            "api_keys": {k: v for k, v in self.api_keys.__dict__.items() if v},
            "auth": {
                "mode": self.auth.mode,
                "username": self.auth.username,
                "password_hash": self.auth.password_hash,
                "secret": self.auth.secret,
                "token_ttl_hours": self.auth.token_ttl_hours,
            },
            "scan": {k: v for k, v in self.scan.__dict__.items()},
            "server": {k: v for k, v in self.server.__dict__.items()},
            "scheduler": {k: v for k, v in self.scheduler.__dict__.items()},
            "notifications": {
                k: v for k, v in self.notifications.__dict__.items()
                if k != "smtp_password"  # no guardar contraseña SMTP en YAML
            },
            "db_path": self.db_path,
            "agent": {
                "mode": self.agent.mode,
                "manager_url": self.agent.manager_url,
                "agent_name": self.agent.agent_name,
                # agent_key desde env var CH_AGENT_KEY, no en YAML
            },
            "siem": {
                k: v for k, v in self.siem.__dict__.items()
                if k not in ("wazuh_api_pass", "elk_pass", "splunk_hec_token")
            },
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        path.chmod(0o600)
        logger.info("Configuración guardada en %s", path)

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def validate(self) -> list[str]:
        """
        Valida la configuración al arrancar.
        Devuelve lista de errores. Lista vacía = config válida.
        """
        errors = []

        # Auth
        if self.auth.mode not in ("jwt", "basic", "none"):
            errors.append(f"auth.mode inválido: '{self.auth.mode}'. Valores: jwt, basic, none")
        if not self.auth.username:
            errors.append("auth.username no puede estar vacío")
        if self.auth.token_ttl_hours < 1 or self.auth.token_ttl_hours > 168:
            errors.append(f"auth.token_ttl_hours fuera de rango: {self.auth.token_ttl_hours} (1-168)")

        # Server
        if not 1 <= self.server.port <= 65535:
            errors.append(f"server.port fuera de rango: {self.server.port}")
        if self.server.tls_cert and not Path(self.server.tls_cert).exists():
            errors.append(f"server.tls_cert no existe: {self.server.tls_cert}")
        if self.server.tls_key and not Path(self.server.tls_key).exists():
            errors.append(f"server.tls_key no existe: {self.server.tls_key}")
        if bool(self.server.tls_cert) != bool(self.server.tls_key):
            errors.append("server.tls_cert y server.tls_key deben especificarse juntos")

        # Scan
        if self.scan.ssh_concurrency < 1 or self.scan.ssh_concurrency > 50:
            errors.append(f"scan.ssh_concurrency fuera de rango: {self.scan.ssh_concurrency} (1-50)")
        if self.scan.max_ww_files < 10:
            errors.append(f"scan.max_ww_files demasiado bajo: {self.scan.max_ww_files}")
        if self.scan.ssh_key_path:
            key = Path(self.scan.ssh_key_path).expanduser()
            if not key.exists():
                errors.append(f"scan.ssh_key_path no existe: {key}")
            elif oct(key.stat().st_mode & 0o777) not in ("0o600", "0o400"):
                errors.append(
                    f"scan.ssh_key_path tiene permisos inseguros: {key} "
                    f"(actual: {oct(key.stat().st_mode & 0o777)}, requerido: 600)"
                )

        # Scheduler
        for field, val in [
            ("audit_hour", self.scheduler.audit_hour),
            ("malware_hour", self.scheduler.malware_hour),
            ("network_hour", self.scheduler.network_hour),
        ]:
            if not 0 <= val <= 23:
                errors.append(f"scheduler.{field} fuera de rango: {val} (0-23)")
        if not 0 <= self.scheduler.malware_day <= 6:
            errors.append(f"scheduler.malware_day fuera de rango: {self.scheduler.malware_day} (0-6)")

        # Notificaciones
        if self.notifications.email_enabled:
            if not self.notifications.smtp_host:
                errors.append("notifications.smtp_host requerido cuando email_enabled=true")
            if not self.notifications.email_to:
                errors.append("notifications.email_to requerido cuando email_enabled=true")
            if not self.notifications.smtp_user:
                errors.append("notifications.smtp_user requerido cuando email_enabled=true")
        if self.notifications.webhook_enabled:
            if not self.notifications.webhook_url:
                errors.append("notifications.webhook_url requerido cuando webhook_enabled=true")
            elif not self.notifications.webhook_url.startswith("https://"):
                errors.append("notifications.webhook_url debe usar HTTPS")
        if self.notifications.min_level not in ("info", "warning", "critical"):
            errors.append(f"notifications.min_level inválido: '{self.notifications.min_level}'")

        return errors
