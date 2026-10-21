"""Claves de host SSH (TOFU): la primera conexión guarda la clave y una distinta corta la conexión.

Antes no se verificaba (known_hosts=None): quien suplantara el equipo recibía la contraseña."""
import asyncssh
import pytest

from cyberhound.core.database import Database
from cyberhound.core.ssh_host_keys import HostKeyStore, known_hosts_line
from cyberhound.scanners.ssh_audit import RemoteAuditor, SSHCredentials


async def _server(host_key, port=0):
    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return password == "pw"

    async def handle(process):
        process.stdout.write("ok\n")
        process.exit(0)
    return await asyncssh.create_server(Server, "127.0.0.1", port, process_factory=handle,
                                        server_host_keys=[host_key])


@pytest.fixture
async def db(tmp_path):
    d = Database(tmp_path / "ch.db")
    await d.init()
    return d


def test_linea_known_hosts():
    assert known_hosts_line("10.0.0.5", 22, "ssh-ed25519 AAA") == "10.0.0.5 ssh-ed25519 AAA\n"
    assert known_hosts_line("10.0.0.5", 2222, "ssh-ed25519 AAA") == "[10.0.0.5]:2222 ssh-ed25519 AAA\n"


async def test_primera_conexion_guarda_y_una_clave_distinta_se_rechaza(db):
    k1, k2 = asyncssh.generate_private_key("ssh-ed25519"), asyncssh.generate_private_key("ssh-ed25519")
    server = await _server(k1)
    port = server.sockets[0].getsockname()[1]
    auditor = RemoteAuditor(SSHCredentials(username="u", port=port, password="pw", use_server_keys=False),
                            host_keys=HostKeyStore(db))
    try:
        async with await auditor._connect("127.0.0.1") as conn:
            assert (await conn.run("x")).stdout == "ok\n"
        [row] = await db.list_ssh_host_keys()
        assert (row["host"], row["port"], row["fingerprint"]) == ("127.0.0.1", port, k1.get_fingerprint())
        async with await auditor._connect("127.0.0.1"):           # la misma clave: entra
            pass
        assert (await db.get_ssh_host_key("127.0.0.1", port))["last_seen"] >= row["last_seen"]

        # otro servidor en el mismo puerto con otra clave: suplantación
        server.close()
        await server.wait_closed()
        server = await _server(k2, port)
        res = await auditor.audit_host("127.0.0.1")
        assert res.status == "hostkey_changed" and "Credenciales SSH" in res.error
        out = await auditor._run_remote_action("127.0.0.1", {"action": "ufw_enable"})
        assert out["ok"] is False and "suplantación" in out["msg"]
        assert (await db.get_ssh_host_key("127.0.0.1", port))["fingerprint"] == k1.get_fingerprint()

        # el administrador la olvida: la siguiente conexión guarda la nueva
        assert await db.delete_ssh_host_key("127.0.0.1", port)
        async with await auditor._connect("127.0.0.1"):
            pass
        assert (await db.get_ssh_host_key("127.0.0.1", port))["fingerprint"] == k2.get_fingerprint()
    finally:
        server.close()
