"""
Ejecutor de comandos del sistema para CyberHound.

Principios:
- Todo I/O pesado va a ThreadPoolExecutor para no bloquear el event loop.
- Los errores NUNCA se silencian: se loguean con contexto completo.
- Los timeouts son obligatorios en todas las llamadas.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from cyberhound.core.logging import get_logger

logger = get_logger("executor")

# Pool global para operaciones de disco/CPU intensivas
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ch_worker")


async def run_command(
    cmd: list[str],
    timeout: int = 60,
    check: bool = False,
    input_data: str | None = None,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    """
    Ejecuta un comando de sistema de forma asíncrona.
    Nunca silencia errores: los loguea y relanza si check=True.
    """
    logger.debug("Ejecutando: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            env=env,
        )
    except FileNotFoundError:
        logger.debug("Comando no encontrado (no disponible en este entorno): %s", cmd[0])
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: command not found")
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input_data.encode() if input_data else None),
            timeout=timeout,
        )
    except TimeoutError:
        proc.kill()
        logger.error("Comando agotó el timeout (%ds): %s", timeout, " ".join(cmd))
        raise

    result = subprocess.CompletedProcess(
        cmd, proc.returncode,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )

    if result.returncode != 0:
        logger.debug(
            "Comando retornó %d: %s\nstderr: %s",
            result.returncode, " ".join(cmd), result.stderr[:500],
        )

    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )

    return result


async def read_file_async(path: str, max_bytes: int = 10 * 1024 * 1024) -> str | None:
    """
    Lee un fichero de forma asíncrona usando aiofiles si está disponible,
    con fallback a ThreadPoolExecutor.
    Loguea explícitamente si falla por permisos (información de seguridad).
    """
    try:
        try:
            import aiofiles
            async with aiofiles.open(path, encoding="utf-8", errors="replace") as f:
                content = await f.read(max_bytes)
            return content
        except ImportError:
            # Fallback a ThreadPoolExecutor
            loop = asyncio.get_event_loop()
            def _read() -> str:
                with open(path, encoding="utf-8", errors="replace") as f:
                    return f.read(max_bytes)
            return await loop.run_in_executor(_pool, _read)

    except PermissionError:
        logger.warning(
            "Sin permiso para leer %s — puede estar protegido por SELinux/AppArmor. "
            "Este fallo es información de seguridad relevante.",
            path,
        )
        return None
    except FileNotFoundError:
        logger.debug("Fichero no encontrado: %s", path)
        return None
    except OSError as e:
        logger.error("Error leyendo %s: %s", path, e)
        return None


async def find_files_async(
    root: str,
    pattern: str = "*",
    exclude_prefixes: list[str] | None = None,
    max_size_bytes: int = 50 * 1024 * 1024,
    timeout: int = 30,
) -> list[str]:
    """
    Búsqueda de ficheros en background sin bloquear el event loop.
    Los errores de permisos se loguean, no se silencian.
    """
    excludes = exclude_prefixes or ["/proc", "/sys", "/dev", "/run"]

    def _find() -> list[str]:
        from pathlib import Path
        results = []
        try:
            for p in Path(root).rglob(pattern):
                if any(str(p).startswith(ex) for ex in excludes):
                    continue
                try:
                    if p.is_file() and p.stat().st_size <= max_size_bytes:
                        results.append(str(p))
                except PermissionError:
                    logger.warning(
                        "Sin permiso para stat %s — posible restricción SELinux/AppArmor", p
                    )
                except OSError as e:
                    logger.debug("OSError en %s: %s", p, e)
        except PermissionError as e:
            logger.warning("Sin permiso para recorrer %s: %s", root, e)
        except OSError as e:
            logger.error("Error recorriendo %s: %s", root, e)
        return results

    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_pool, _find),
            timeout=timeout,
        )
    except TimeoutError:
        logger.error("find_files_async agotó el timeout (%ds) en %s", timeout, root)
        return []


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None
