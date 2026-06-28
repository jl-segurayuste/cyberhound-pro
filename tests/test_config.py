"""Tests de configuración — adaptados a la API real de CyberHoundConfig."""
import pytest
from cyberhound.core.config import CyberHoundConfig


class TestConfigBasic:

    def test_config_loads_defaults(self):
        """CyberHoundConfig carga con valores por defecto."""
        cfg = CyberHoundConfig()
        assert cfg is not None
        assert hasattr(cfg, "auth")
        assert hasattr(cfg, "server")

    def test_config_has_required_sections(self):
        """Config tiene las secciones principales."""
        cfg = CyberHoundConfig()
        assert hasattr(cfg, "auth")
        assert hasattr(cfg, "server")
        assert hasattr(cfg, "scan")
        assert hasattr(cfg, "api_keys")

    def test_server_port_default(self):
        """Puerto por defecto es razonable."""
        cfg = CyberHoundConfig()
        port = getattr(cfg.server, "port", None)
        if port is not None:
            assert 1024 <= port <= 65535

    def test_auth_section_exists(self):
        """Sección de auth existe y tiene campos."""
        cfg = CyberHoundConfig()
        auth = cfg.auth
        assert auth is not None

    def test_api_keys_section(self):
        """APIKeys tiene los campos esperados."""
        cfg = CyberHoundConfig()
        keys = cfg.api_keys
        assert hasattr(keys, "shodan")
        assert hasattr(keys, "virustotal")
        assert hasattr(keys, "abuseipdb")

    def test_hash_password(self):
        """hash_password genera un hash de contraseña."""
        cfg = CyberHoundConfig()
        h = cfg.hash_password("testpassword123")
        assert h and isinstance(h, str)
        assert h != "testpassword123"

    def test_load_returns_config(self, tmp_path):
        """load() devuelve una instancia de CyberHoundConfig."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("server:\n  port: 9443\n")
        cfg = CyberHoundConfig.load(yaml_file)
        assert isinstance(cfg, CyberHoundConfig)

    def test_save_creates_file(self, tmp_path):
        """save() crea el fichero de configuración."""
        cfg = CyberHoundConfig()
        yaml_file = tmp_path / "config.yaml"
        cfg.save(yaml_file)
        assert yaml_file.exists()

    def test_scan_section_exists(self):
        """Sección de scan existe."""
        cfg = CyberHoundConfig()
        assert hasattr(cfg, "scan")

    def test_config_is_reloadable(self, tmp_path):
        """Config guardada puede recargarse."""
        cfg = CyberHoundConfig()
        yaml_file = tmp_path / "config.yaml"
        cfg.save(yaml_file)
        cfg2 = CyberHoundConfig.load(yaml_file)
        assert isinstance(cfg2, CyberHoundConfig)
