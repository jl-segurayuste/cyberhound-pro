"""Credenciales SSH guardadas (cyberhound/core/ssh_credentials.py) y con qué claves conecta asyncssh."""
import asyncssh
import pytest

from cyberhound.core import ssh_credentials as sc
from cyberhound.scanners.ssh_audit import SSHCredentials

KEY = "k" * 64


def test_cifrado_ligado_a_la_organizacion():
    sealed = sc.seal("secreto", KEY, "acme")
    assert sealed.startswith("enc:v1:") and "secreto" not in sealed
    assert sc.unseal(sealed, KEY, "acme") == "secreto"
    assert sc.unseal(sealed, KEY, "contoso") is None          # copiada a otra organización no sirve
    assert sc.unseal(sealed, "otra" * 16, "acme") is None     # ni con otro auth.secret
    assert sc.unseal("secreto", KEY, "acme") is None           # en claro no se acepta


def test_generar_par_de_claves():
    d = sc.prepare({"name": " Servidores ", "username": "auditor", "port": 2222, "kind": "generate"}, KEY, "acme")
    assert d["name"] == "Servidores" and d["port"] == 2222 and d["kind"] == "key"
    assert d["public_key"].startswith("ssh-ed25519 ") and d["fingerprint"].startswith("SHA256:")
    pem = sc.unseal(d["secret"], KEY, "acme")
    assert asyncssh.import_private_key(pem).get_fingerprint() == d["fingerprint"]
    creds = sc.to_ssh_credentials({**d, "id": "0a1b2c3d"}, KEY, "acme")
    assert creds.private_key == pem and creds.username == "auditor" and creds.port == 2222
    assert creds.use_server_keys is False
    assert "secret" not in sc.public_view({**d, "id": "x"})


def test_pegar_clave_cifrada():
    k = asyncssh.generate_private_key("ssh-ed25519")
    pem = k.export_private_key("openssh", passphrase="frase").decode()
    base = {"name": "k", "kind": "key", "private_key": pem}
    with pytest.raises(ValueError, match="frase de paso"):
        sc.prepare(base, KEY, "acme")
    with pytest.raises(ValueError, match="frase de paso"):
        sc.prepare({**base, "passphrase": "mala"}, KEY, "acme")
    d = sc.prepare({**base, "passphrase": "frase"}, KEY, "acme")
    assert d["fingerprint"] == k.get_fingerprint()
    # se guarda sin frase de paso (ya va cifrada): conectar no la necesita
    assert asyncssh.import_private_key(sc.unseal(d["secret"], KEY, "acme")).get_fingerprint() == k.get_fingerprint()


@pytest.mark.parametrize("body", [
    {"name": "", "kind": "password", "password": "x"},
    {"name": "a", "kind": "password", "password": ""},
    {"name": "a", "kind": "otra"},
    {"name": "a", "kind": "key", "private_key": "no es una clave"},
    {"name": "a", "kind": "password", "password": "x", "username": "root; reboot"},
    {"name": "a", "kind": "password", "password": "x", "port": 70000},
])
def test_validacion(body):
    with pytest.raises(ValueError):
        sc.prepare(body, KEY, "acme")


def test_edicion_parcial_no_toca_el_secreto():
    assert sc.prepare({"name": "nuevo"}, KEY, "acme", partial=True) == {"name": "nuevo"}
    d = sc.prepare({"kind": "password", "password": "p"}, KEY, "acme", partial=True)
    assert set(d) == {"kind", "secret", "public_key", "fingerprint"}


def test_credencial_que_no_se_puede_descifrar():
    d = sc.prepare({"name": "a", "kind": "password", "password": "p"}, KEY, "acme")
    with pytest.raises(ValueError, match="descifrar"):
        sc.to_ssh_credentials(d, KEY, "contoso")


def test_sin_claves_del_servidor():
    """asyncssh, sin client_keys, prueba ~/.ssh/id_* y el agente; con una lista vacía también."""
    tenant = SSHCredentials(password="p", use_server_keys=False).to_asyncssh_opts()
    assert tenant["client_keys"] is None and tenant["agent_path"] is None and tenant["password"] == "p"
    assert "client_keys" not in SSHCredentials(password="p").to_asyncssh_opts()      # la plataforma, como antes
    k = asyncssh.generate_private_key("ssh-ed25519")
    opts = SSHCredentials(private_key=k.export_private_key("openssh").decode(), use_server_keys=False).to_asyncssh_opts()
    assert [c.get_fingerprint() for c in opts["client_keys"]] == [k.get_fingerprint()]
    assert opts["agent_path"] is None
    # y asyncssh, con esas opciones, no carga ninguna clave por su cuenta
    assert asyncssh.SSHClientConnectionOptions(**tenant).client_keys is None


async def _server(accepted_key, password="pw-buena"):
    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, pw):
            return pw == password

        def public_key_auth_supported(self):
            return True

        def validate_public_key(self, username, key):
            return key.public_data == accepted_key.public_data

    async def handle(process):
        process.stdout.write("ok\n")
        process.exit(0)
    return await asyncssh.create_server(Server, "127.0.0.1", 0, process_factory=handle,
                                        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")])


async def test_una_organizacion_no_entra_con_la_clave_de_la_plataforma(tmp_path, monkeypatch):
    """Con contraseña (incorrecta) y sin client_keys, asyncssh probaba antes ~/.ssh/id_* del servidor."""
    from cyberhound.scanners.ssh_audit import RemoteAuditor
    platform_key = asyncssh.generate_private_key("ssh-ed25519")
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh/id_ed25519").write_bytes(platform_key.export_private_key("openssh"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    server = await _server(platform_key)
    port = server.sockets[0].getsockname()[1]
    try:
        async def status(creds):
            return (await RemoteAuditor(creds).audit_host("127.0.0.1")).status

        # comportamiento de antes (y de la plataforma): la clave por defecto del servidor entra
        old = SSHCredentials(username="u", port=port, password="mala")
        async with asyncssh.connect("127.0.0.1", **old.to_asyncssh_opts()) as conn:
            assert (await conn.run("x")).stdout == "ok\n"
        # una organización: solo su contraseña, y además el fallo se informa como tal
        tenant = SSHCredentials(username="u", port=port, password="mala", use_server_keys=False)
        assert await status(tenant) == "auth_failed"
        good = SSHCredentials(username="u", port=port, password="pw-buena", use_server_keys=False)
        async with asyncssh.connect("127.0.0.1", **good.to_asyncssh_opts()) as conn:
            assert (await conn.run("x")).stdout == "ok\n"
        # su clave guardada entra; la del servidor ya no se ofrece
        own = asyncssh.generate_private_key("ssh-ed25519")
        server.close()
        server = await _server(own)
        port = server.sockets[0].getsockname()[1]
        mine = SSHCredentials(username="u", port=port, private_key=own.export_private_key("openssh").decode(),
                              use_server_keys=False)
        async with asyncssh.connect("127.0.0.1", **mine.to_asyncssh_opts()) as conn:
            assert (await conn.run("x")).stdout == "ok\n"
    finally:
        server.close()
