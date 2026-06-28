"""
Punto de entrada de CyberHound Pro.
NO instala dependencias en runtime. Si faltan, informa claramente.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def _check_dependencies() -> list[str]:
    """Verifica dependencias sin instalar nada."""
    required = [
        "aiohttp", "aiosqlite", "yaml", "jwt",
        "cryptography", "colorama", "jinja2",
    ]
    missing = []
    import importlib
    for mod in required:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(mod)
    return missing


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cyberhound",
        description="CyberHound Pro v6.0 — Plataforma de seguridad para PYMEs",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # web
    web_p = sub.add_parser("web", help="Lanza la interfaz web")
    web_p.add_argument("--port", type=int, default=8443)
    web_p.add_argument("--host", default="0.0.0.0")
    web_p.add_argument("--config", default=str(Path.home() / ".cyberhound" / "config.yaml"))
    web_p.add_argument("--no-auth", action="store_true", help="Sin autenticación (solo localhost)")
    web_p.add_argument("--tls-cert", help="Ruta al certificado TLS")
    web_p.add_argument("--tls-key", help="Ruta a la clave TLS privada")

    # setup — configura contraseña y genera config inicial
    setup_p = sub.add_parser("setup", help="Configuración inicial (contraseña, API keys)")
    setup_p.add_argument("--config", default=str(Path.home() / ".cyberhound" / "config.yaml"))

    # version
    sub.add_parser("version", help="Muestra la versión")

    args = parser.parse_args()

    if args.command == "version":
        print("CyberHound Pro v6.0.0")
        return

    # Verificar dependencias antes de importar nada más
    missing = _check_dependencies()
    if missing:
        print(
            f"\n❌ Dependencias faltantes: {missing}\n\n"
            "Para instalar:\n"
            "  python3 -m venv ~/.venv/cyberhound\n"
            "  source ~/.venv/cyberhound/bin/activate\n"
            "  pip install -e /ruta/al/paquete/cyberhound\n"
            "\nO si tienes el paquete:\n"
            "  pip install cyberhound\n",
            file=sys.stderr,
        )
        sys.exit(1)

    from cyberhound.core.config import CyberHoundConfig
    from cyberhound.core.logging import setup_logging

    if args.command == "setup":
        _run_setup(Path(args.config))
        return

    # Cargar configuración
    cfg = CyberHoundConfig.load(Path(args.config))
    setup_logging(structured=(cfg.server.log_dir != ""))

    # Sobrescribir con flags de CLI
    if hasattr(args, "port"):
        cfg.server.port = args.port
    if hasattr(args, "host"):
        cfg.server.host = args.host
    if getattr(args, "no_auth", False):
        cfg.auth.mode = "none"
        cfg.auth.localhost_only = True
    if getattr(args, "tls_cert", None):
        cfg.server.tls_cert = args.tls_cert
    if getattr(args, "tls_key", None):
        cfg.server.tls_key = args.tls_key

    from cyberhound.api.server import CyberHoundServer
    server = CyberHoundServer(cfg)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n✓ CyberHound detenido.")


def _run_setup(config_path: Path) -> None:
    """Asistente de configuración inicial interactivo."""
    from cyberhound.core.config import CyberHoundConfig

    print("\n🐾 CyberHound Pro — Configuración inicial\n")

    cfg = CyberHoundConfig()
    if config_path.exists():
        cfg = CyberHoundConfig.load(config_path)
        print(f"Configuración existente cargada desde {config_path}")

    # Contraseña de administrador
    import getpass
    print("\n── Credenciales de acceso a la interfaz web ──")
    username = input(f"Usuario admin [{cfg.auth.username}]: ").strip() or cfg.auth.username
    password = getpass.getpass("Contraseña (mínimo 8 caracteres): ")
    if len(password) < 8:
        print("❌ La contraseña debe tener al menos 8 caracteres.")
        sys.exit(1)
    confirm = getpass.getpass("Repetir contraseña: ")
    if password != confirm:
        print("❌ Las contraseñas no coinciden.")
        sys.exit(1)

    cfg.auth.username = username
    cfg.auth.password_hash = CyberHoundConfig.hash_password(password)

    # Puerto y auth mode
    print("\n── Configuración del servidor ──")
    port_str = input(f"Puerto [{cfg.server.port}]: ").strip()
    if port_str.isdigit():
        cfg.server.port = int(port_str)

    auth_mode = input("Modo de autenticación (jwt/basic) [jwt]: ").strip() or "jwt"
    cfg.auth.mode = auth_mode if auth_mode in ("jwt", "basic") else "jwt"

    # API keys opcionales
    print("\n── API Keys (opcionales, Enter para omitir) ──")
    for key_name in ("shodan", "virustotal", "abuseipdb", "greynoise", "otx", "hibp"):
        current = getattr(cfg.api_keys, key_name)
        display = f"{current[:4]}***" if current else "no configurada"
        val = input(f"{key_name} [{display}]: ").strip()
        if val:
            setattr(cfg.api_keys, key_name, val)

    # SSH key por defecto
    print("\n── Configuración SSH (para análisis de hosts remotos) ──")
    default_key = str(Path.home() / ".ssh" / "id_ed25519")
    ssh_key = input(f"Ruta clave SSH privada [{default_key}]: ").strip() or default_key
    if Path(ssh_key).exists():
        cfg.scan.ssh_key_path = ssh_key
        print(f"✓ Clave SSH configurada: {ssh_key}")
    else:
        print(f"⚠ Clave no encontrada en {ssh_key}. Configúrala manualmente en config.yaml")

    cfg.save(config_path)
    print(f"\n✓ Configuración guardada en {config_path}")
    print(f"\nPara lanzar:\n  cyberhound web --port {cfg.server.port}\n")


if __name__ == "__main__":
    main()
