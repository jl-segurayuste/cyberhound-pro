"""Servidor SSH de pruebas para la batería funcional (solo 127.0.0.1, datos de usar y tirar).

Acepta al usuario "auditor" con la contraseña de CH_E2E_SSH_PASSWORD o con cualquier clave de
<trabajo>/ssh_authorized_keys, que la propia batería rellena con la clave pública que genera
CyberHound. Los comandos se ejecutan en esta máquina como el usuario que lanza la batería (sin
sudo): la auditoría SSH sale parcial, pero el camino es el real de punta a punta. Si aparece
<trabajo>/ssh_rotate, vuelve a arrancar en el mismo puerto con otra clave de host (como un equipo
suplantado o reinstalado) para probar que CyberHound no se conecta.

    python sshd.py <puerto> <directorio de trabajo>
"""
import asyncio
import os
import sys
from pathlib import Path

import asyncssh

PORT, WORK = int(sys.argv[1]), Path(sys.argv[2])
USER, PASSWORD = "auditor", os.environ["CH_E2E_SSH_PASSWORD"]
AUTHORIZED = WORK / "ssh_authorized_keys"
ROTATE = WORK / "ssh_rotate"


class Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == USER and password == PASSWORD

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key) -> bool:
        if username != USER or not AUTHORIZED.exists():
            return False
        lines = [ln for ln in AUTHORIZED.read_text().splitlines() if ln.strip()]
        return any(asyncssh.import_public_key(ln).public_data == key.public_data for ln in lines)


async def handle(process) -> None:
    cmd = process.command or "true"
    proc = await asyncio.create_subprocess_shell(cmd, stdin=asyncio.subprocess.PIPE,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    # Solo "python3 -" lee de stdin (el script de auditoría o de fix va por ahí)
    data = (await process.stdin.read()).encode() if cmd.rstrip().endswith(" -") else b""
    out, err = await proc.communicate(data)
    process.stdout.write(out.decode(errors="replace"))
    process.stderr.write(err.decode(errors="replace"))
    process.exit(proc.returncode or 0)


async def serve():
    return await asyncssh.create_server(Server, "127.0.0.1", PORT, process_factory=handle,
                                        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")])


async def main() -> None:
    server = await serve()
    while True:
        await asyncio.sleep(0.5)
        if ROTATE.exists():
            ROTATE.unlink()
            server.close()
            await server.wait_closed()
            server = await serve()


asyncio.run(main())
