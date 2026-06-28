"""
Descubrimiento de red orientado a PYMEs.

Obtiene de cada host:
- IP, MAC, fabricante (OUI lookup)
- SO y versión (nmap OS detection)
- Puertos abiertos y servicios con versión
- Hostname/PTR DNS
- Vulnerabilidades CVE asociadas a los servicios detectados (nmap NSE vuln)
- Si tiene SSH: lo marca como candidato para audit completo

No requiere agentes en los hosts remotos para la fase de descubrimiento.
"""
from __future__ import annotations

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger

logger = get_logger("network")


@dataclass
class OpenPort:
    port:     int
    protocol: str       # tcp | udp
    state:    str       # open | filtered
    service:  str       # http, ssh, smb…
    product:  str = ""  # Apache httpd, OpenSSH…
    version:  str = ""
    cpe:      str = ""  # cpe:/a:apache:http_server:2.4.51

    @property
    def label(self) -> str:
        parts = [self.service]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class NetworkDevice:
    ip:           str
    mac:          str = ""
    vendor:       str = ""       # del OUI de la MAC
    hostname:     str = ""
    os_name:      str = ""
    os_accuracy:  int = 0
    open_ports:   list[OpenPort] = field(default_factory=list)
    cves:         list[str] = field(default_factory=list)
    has_ssh:      bool = False
    ssh_port:     int = 22
    scan_status:  str = "pending"   # pending | scanned | unreachable
    raw_nmap_xml: str = ""

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "mac":         self.mac,
            "vendor":      self.vendor,
            "hostname":    self.hostname,
            "os_name":     self.os_name,
            "os_accuracy": self.os_accuracy,
            "has_ssh":     self.has_ssh,
            "ssh_port":    self.ssh_port,
            "scan_status": self.scan_status,
            "open_ports":  [
                {"port": p.port, "protocol": p.protocol, "service": p.service,
                 "product": p.product, "version": p.version, "cpe": p.cpe}
                for p in self.open_ports
            ],
            "cves": self.cves,
        }

    @property
    def risk_level(self) -> str:
        """Nivel de riesgo rápido basado en puertos/servicios detectados."""
        risky_services = {"telnet", "ftp", "rsh", "rlogin", "rexec", "vnc", "rdp", "smb"}
        services = {p.service.lower() for p in self.open_ports}
        if services & risky_services:
            return "high"
        if self.cves:
            return "high"
        if len(self.open_ports) > 10:
            return "medium"
        return "low"


class NetworkScanner:
    """
    Escaneo de red en dos fases:
    1. Ping sweep para descubrir hosts vivos (rápido)
    2. Port scan + OS detection + vuln NSE en hosts vivos (profundo, en paralelo)
    """

    def __init__(self, nmap_timeout: int = 180) -> None:
        self.nmap_timeout = nmap_timeout
        self._has_nmap = command_exists("nmap")
        self._has_arpscan = command_exists("arp-scan")

        if not self._has_nmap:
            logger.warning(
                "nmap no encontrado. Instala con: sudo apt install nmap\n"
                "Sin nmap el escaneo de puertos y OS detection no estará disponible."
            )

    # ── Fase 1: Descubrimiento ────────────────────────────────────────────────

    async def discover_hosts(
        self,
        networks: Optional[list[str]] = None,
        exclude_ips: Optional[list[str]] = None,
    ) -> list[str]:
        """Devuelve lista de IPs activas en la red."""
        target_networks = networks or await self._detect_local_networks()
        if not target_networks:
            logger.error("No se detectaron redes locales.")
            return []

        logger.info("Iniciando descubrimiento en: %s", target_networks)
        all_ips: set[str] = set()

        tasks = [self._ping_sweep(net) for net in target_networks]
        if self._has_arpscan:
            tasks.append(self._arp_scan())
        tasks.append(self._arp_cache())

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                all_ips.update(res)
            elif isinstance(res, Exception):
                logger.error("Error en fase de descubrimiento: %s", res)

        # Excluir IPs propias y las especificadas
        exclude = set(exclude_ips or [])
        try:
            proc = await run_command(["hostname", "-I"], timeout=5)
            for ip in proc.stdout.split():
                exclude.add(ip.strip())
        except Exception:
            pass

        discovered = sorted(all_ips - exclude)
        logger.info("Hosts descubiertos: %d → %s", len(discovered), discovered)
        return discovered

    async def _detect_local_networks(self) -> list[str]:
        networks = []
        try:
            proc = await run_command(["ip", "route", "show"], timeout=10)
            for line in proc.stdout.splitlines():
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+\S+\s+proto\s+kernel", line)
                if m:
                    net = m.group(1)
                    prefix = int(net.split("/")[1])
                    if not net.startswith(("127.", "169.254.")) and prefix >= 16:
                        networks.append(net)
        except Exception as e:
            logger.error("Error detectando redes locales: %s", e)
        return networks

    async def _ping_sweep(self, network: str) -> list[str]:
        if not self._has_nmap:
            return []
        try:
            proc = await run_command(
                ["nmap", "-sn", "-T4", "--open", "-oG", "-", network],
                timeout=self.nmap_timeout,
            )
            hosts = []
            for line in proc.stdout.splitlines():
                m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    hosts.append(m.group(1))
            return hosts
        except Exception as e:
            logger.error("Ping sweep falló en %s: %s", network, e)
            return []

    async def _arp_scan(self) -> list[str]:
        try:
            proc = await run_command(["arp-scan", "--localnet"], timeout=30)
            return [
                m.group(1)
                for line in proc.stdout.splitlines()
                if (m := re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+", line))
            ]
        except Exception as e:
            logger.error("arp-scan falló: %s", e)
            return []

    async def _arp_cache(self) -> list[str]:
        try:
            proc = await run_command(["arp", "-n"], timeout=10)
            return [
                m.group(1)
                for line in proc.stdout.splitlines()
                if (m := re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(?!incomplete)(\S+)", line))
            ]
        except Exception as e:
            logger.debug("arp cache read failed: %s", e)
            return []

    # ── Fase 2: Escaneo profundo ──────────────────────────────────────────────

    async def deep_scan(
        self,
        ip: str,
        vuln_scan: bool = False,
    ) -> NetworkDevice:
        """
        Escaneo completo de un host: puertos, OS, servicios, versiones.
        vuln_scan=True activa los NSE scripts de vulnerabilidades (más lento).
        """
        device = NetworkDevice(ip=ip)

        if not self._has_nmap:
            device.scan_status = "no_nmap"
            logger.warning("nmap no disponible para escanear %s", ip)
            return device

        # Resolución DNS inversa
        try:
            proc = await run_command(["dig", "+short", "-x", ip], timeout=10)
            hostname = proc.stdout.strip().rstrip(".")
            if hostname:
                device.hostname = hostname
        except Exception:
            pass

        # Construcción del comando nmap
        nmap_args = [
            "nmap",
            "-sV",           # versión de servicios
            "-O",            # OS detection (requiere root)
            "--osscan-guess",
            "-T4",
            "-p", "21-23,25,53,80,110,111,139,143,389,443,445,465,587,993,995,"
                  "1433,1521,1723,3306,3389,5432,5900,5985,6379,8080,8443,8888,27017",
            "--open",
            "-oX", "-",      # salida XML a stdout
        ]
        if vuln_scan:
            nmap_args += ["--script", "vuln,exploit"]
        nmap_args.append(ip)

        try:
            proc = await run_command(nmap_args, timeout=self.nmap_timeout)
            if proc.returncode == 0 and proc.stdout.strip():
                device = self._parse_nmap_xml(proc.stdout, device)
                device.scan_status = "scanned"
            elif "requires root" in proc.stderr.lower():
                logger.warning(
                    "nmap OS detection requiere root en %s. "
                    "Ejecutando sin -O…", ip
                )
                nmap_args.remove("-O")
                nmap_args.remove("--osscan-guess")
                proc2 = await run_command(nmap_args, timeout=self.nmap_timeout)
                if proc2.stdout.strip():
                    device = self._parse_nmap_xml(proc2.stdout, device)
                device.scan_status = "scanned_no_os"
            else:
                device.scan_status = "error"
                logger.error("nmap error en %s: %s", ip, proc.stderr[:300])
        except asyncio.TimeoutError:
            device.scan_status = "timeout"
            logger.warning("nmap timeout en %s", ip)
        except Exception as e:
            device.scan_status = "error"
            logger.error("Error escaneando %s: %s", ip, e)

        return device

    def _parse_nmap_xml(self, xml_output: str, device: NetworkDevice) -> NetworkDevice:
        """Parsea la salida XML de nmap y rellena el NetworkDevice."""
        try:
            root = ET.fromstring(xml_output)
            device.raw_nmap_xml = xml_output

            for host_el in root.findall("host"):
                # Estado del host
                status = host_el.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # MAC y vendor
                for addr in host_el.findall("address"):
                    if addr.get("addrtype") == "mac":
                        device.mac = addr.get("addr", "")
                        device.vendor = addr.get("vendor", "")

                # OS detection
                os_el = host_el.find("os")
                if os_el is not None:
                    matches = os_el.findall("osmatch")
                    if matches:
                        best = max(matches, key=lambda x: int(x.get("accuracy", "0")))
                        device.os_name = best.get("name", "")
                        device.os_accuracy = int(best.get("accuracy", "0"))

                # Hostname
                hostnames = host_el.find("hostnames")
                if hostnames is not None and not device.hostname:
                    for hn in hostnames.findall("hostname"):
                        device.hostname = hn.get("name", "")
                        break

                # Puertos
                ports_el = host_el.find("ports")
                if ports_el is not None:
                    for port_el in ports_el.findall("port"):
                        state_el = port_el.find("state")
                        if state_el is None or state_el.get("state") != "open":
                            continue

                        service_el = port_el.find("service")
                        port = OpenPort(
                            port=     int(port_el.get("portid", "0")),
                            protocol= port_el.get("protocol", "tcp"),
                            state=    "open",
                            service=  service_el.get("name", "") if service_el is not None else "",
                            product=  service_el.get("product", "") if service_el is not None else "",
                            version=  service_el.get("version", "") if service_el is not None else "",
                            cpe=      (service_el.find("cpe").text if service_el is not None
                                       and service_el.find("cpe") is not None else ""),
                        )
                        device.open_ports.append(port)

                        # Marcar SSH
                        if port.service in ("ssh", "openssh") or port.port == 22:
                            device.has_ssh = True
                            device.ssh_port = port.port

                # CVEs desde scripts NSE
                for script in host_el.iter("script"):
                    script_id = script.get("id", "")
                    if "vuln" in script_id or "cve" in script_id.lower():
                        output = script.get("output", "")
                        cve_matches = re.findall(r"CVE-\d{4}-\d+", output)
                        device.cves.extend(cve_matches)

                device.cves = list(set(device.cves))

        except ET.ParseError as e:
            logger.error("Error parseando XML de nmap: %s", e)

        return device

    async def scan_network(
        self,
        networks: Optional[list[str]] = None,
        exclude_ips: Optional[list[str]] = None,
        deep: bool = True,
        vuln_scan: bool = False,
        concurrency: int = 10,
    ) -> list[NetworkDevice]:
        """
        Escaneo completo de la red:
        1. Descubrimiento
        2. Escaneo profundo en paralelo (con límite de concurrencia)
        """
        ips = await self.discover_hosts(networks=networks, exclude_ips=exclude_ips)
        if not ips:
            return []

        if not deep:
            return [NetworkDevice(ip=ip, scan_status="discovered") for ip in ips]

        sem = asyncio.Semaphore(concurrency)

        async def _scan_one(ip: str) -> NetworkDevice:
            async with sem:
                logger.info("Escaneando %s…", ip)
                return await self.deep_scan(ip, vuln_scan=vuln_scan)

        devices = await asyncio.gather(*[_scan_one(ip) for ip in ips])
        return list(devices)
