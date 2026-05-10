"""
Configuración centralizada de CyberHound.
Fuentes (en orden de precedencia): variables de entorno > config.yaml > defaults.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from cyberhound.core.logging import get_logger

logger = get_logger("config")

DEFAULT_CONFIG_PATH = Path.home() / ".cyberhound" / "config.yaml"


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
    mode:           str  = "jwt"       # jwt | basic | none
    username:       str  = "admin"
    password_hash:  Optional[str] = None  # SHA-256 hex
    secret:         Optional[str] = None
    token_ttl_hours:int  = 8
    localhost_only: bool = False


@dataclass
class ScanSettings:
    ssh_default_user: str  = "root"
    ssh_default_port: int  = 22
    ssh_key_path:     Optional[str] = None
    nmap_timeout:     int  = 120
    ssh_concurrency:  int  = 5
    max_ww_files:     int  = 500       # límite de findings world-writable
    hash_scan_max:    int  = 50


@dataclass
class ServerSettings:
    host:     str  = "0.0.0.0"
    port:     int  = 8443
    tls_cert: Optional[str] = None    # ruta a cert PEM
    tls_key:  Optional[str] = None    # ruta a key PEM
    log_dir:  str  = "/var/log/cyberhound"


@dataclass
class CyberHoundConfig:
    api_keys:   APIKeys       = field(default_factory=APIKeys)
    auth:       AuthSettings  = field(default_factory=AuthSettings)
    scan:       ScanSettings  = field(default_factory=ScanSettings)
    server:     ServerSettings = field(default_factory=ServerSettings)

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

        # API keys desde YAML
        keys_raw = raw.get("api_keys", {})
        cfg.api_keys = APIKeys(
            shodan=     keys_raw.get("shodan"),
            virustotal= keys_raw.get("virustotal"),
            abuseipdb=  keys_raw.get("abuseipdb"),
            greynoise=  keys_raw.get("greynoise"),
            otx=        keys_raw.get("otx"),
            hibp=       keys_raw.get("hibp"),
        )

        # Variables de entorno tienen prioridad sobre YAML
        env_map = {
            "SHODAN_API_KEY":   "shodan",
            "VT_API_KEY":       "virustotal",
            "ABUSEIPDB_KEY":    "abuseipdb",
            "GREYNOISE_KEY":    "greynoise",
            "OTX_KEY":          "otx",
            "HIBP_API_KEY":     "hibp",
        }
        for env_var, attr in env_map.items():
            val = os.environ.get(env_var)
            if val:
                setattr(cfg.api_keys, attr, val)

        # Auth
        auth_raw = raw.get("auth", {})
        cfg.auth = AuthSettings(
            mode=           auth_raw.get("mode", "jwt"),
            username=       auth_raw.get("username", "admin"),
            password_hash=  auth_raw.get("password_hash"),
            secret=         auth_raw.get("secret") or os.environ.get("CH_SECRET"),
            token_ttl_hours=auth_raw.get("token_ttl_hours", 8),
            localhost_only= auth_raw.get("localhost_only", False),
        )

        # Scan
        scan_raw = raw.get("scan", {})
        cfg.scan = ScanSettings(
            ssh_default_user=scan_raw.get("ssh_default_user", "root"),
            ssh_default_port=scan_raw.get("ssh_default_port", 22),
            ssh_key_path=    scan_raw.get("ssh_key_path"),
            nmap_timeout=    scan_raw.get("nmap_timeout", 120),
            ssh_concurrency= scan_raw.get("ssh_concurrency", 5),
            max_ww_files=    scan_raw.get("max_ww_files", 500),
            hash_scan_max=   scan_raw.get("hash_scan_max", 50),
        )

        # Server
        srv_raw = raw.get("server", {})
        cfg.server = ServerSettings(
            host=    srv_raw.get("host", "0.0.0.0"),
            port=    int(srv_raw.get("port", 8443)),
            tls_cert=srv_raw.get("tls_cert"),
            tls_key= srv_raw.get("tls_key"),
            log_dir= srv_raw.get("log_dir", "/var/log/cyberhound"),
        )

        return cfg

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Generar secret persistente si no existe
        if not self.auth.secret:
            import secrets as _s
            self.auth.secret = _s.token_hex(32)
            logger.info("JWT secret generado y guardado en config")
        data = {
            "api_keys": {k: v for k, v in self.api_keys.__dict__.items() if v},
            "auth": {
                "mode":            self.auth.mode,
                "username":        self.auth.username,
                "password_hash":   self.auth.password_hash,
                "secret":          self.auth.secret,
                "token_ttl_hours": self.auth.token_ttl_hours,
            },
            "scan": self.scan.__dict__,
            "server": self.server.__dict__,
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        # Permisos restrictivos — contiene el JWT secret
        path.chmod(0o600)
        logger.info("Configuración guardada en %s", path)

    @staticmethod
    def hash_password(password: str) -> str:
        """Genera el hash SHA-256 para guardar en config.yaml."""
        return hashlib.sha256(password.encode()).hexdigest()
