"""
Scheduler de CyberHound Pro.
Ejecuta auditorías automáticas sin depender del cron del sistema.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

from cyberhound.core.logging import get_logger

logger = get_logger("scheduler")


@dataclass
class ScheduleEntry:
    name:    str
    task_fn: Callable
    hour:    int
    minute:  int = 0
    days:    list[int] = field(default_factory=lambda: list(range(7)))
    enabled: bool = True
    last_run:  Optional[str] = None
    next_run:  Optional[str] = None

    def should_run_now(self) -> bool:
        if not self.enabled:
            return False
        now = datetime.now()
        return now.weekday() in self.days and now.hour == self.hour and now.minute == self.minute

    def compute_next_run(self) -> str:
        now = datetime.now()
        candidate = now.replace(hour=self.hour, minute=self.minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        for _ in range(8):
            if candidate.weekday() in self.days:
                return candidate.isoformat()
            candidate += timedelta(days=1)
        return candidate.isoformat()


class Scheduler:
    def __init__(self) -> None:
        self._entries: list[ScheduleEntry] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def add(self, entry: ScheduleEntry) -> None:
        entry.next_run = entry.compute_next_run()
        self._entries.append(entry)
        day_names = ["lun","mar","mié","jue","vie","sáb","dom"]
        days_str = "todos" if len(entry.days) == 7 else ",".join(day_names[d] for d in entry.days)
        logger.info(
            "Tarea '%s' programada: %02d:%02d (%s) → próxima: %s",
            entry.name, entry.hour, entry.minute, days_str, entry.next_run,
        )

    def list_entries(self) -> list[dict]:
        return [
            {"name": e.name, "hour": e.hour, "minute": e.minute,
             "enabled": e.enabled, "last_run": e.last_run, "next_run": e.next_run}
            for e in self._entries
        ]

    def enable(self, name: str, enabled: bool) -> bool:
        for e in self._entries:
            if e.name == name:
                e.enabled = enabled
                return True
        return False

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.ensure_future(self._loop())
        logger.info("Scheduler iniciado con %d tareas", len(self._entries))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._tick()
            except Exception as e:
                logger.error("Scheduler error: %s", e, exc_info=True)
            now = datetime.now()
            sleep_s = 60 - now.second - now.microsecond / 1_000_000
            await asyncio.sleep(sleep_s)

    async def _tick(self) -> None:
        for entry in self._entries:
            if not entry.should_run_now():
                continue
            logger.info("▶ Ejecutando tarea programada: '%s'", entry.name)
            entry.last_run = datetime.now().isoformat()
            entry.next_run = entry.compute_next_run()
            try:
                await entry.task_fn()
                logger.info("✓ Tarea '%s' completada", entry.name)
            except Exception as e:
                logger.error("✗ Tarea '%s' falló: %s", entry.name, e, exc_info=True)

    async def run_now(self, name: str) -> bool:
        for entry in self._entries:
            if entry.name == name:
                logger.info("Ejecución manual: '%s'", name)
                entry.last_run = datetime.now().isoformat()
                await entry.task_fn()
                return True
        return False


def build_scheduler(app_ref, cfg) -> Scheduler:
    """
    Construye el scheduler con las tareas estándar.
    app_ref debe tener: .cfg, .db, .notification_manager
    """
    s = Scheduler()

    if getattr(cfg, "audit_enabled", True):
        async def _audit():
            from cyberhound.scanners.hardening import HardeningAuditor
            db = app_ref.db
            scan_id = await db.create_scan("audit", triggered_by="scheduler")
            try:
                findings = await HardeningAuditor.full_audit(cfg=app_ref.cfg)
                findings = await db.filter_suppressed(findings)
                await db.complete_scan(scan_id, findings)
                critical = [f for f in findings if f.severity == "critical"]
                if critical:
                    await app_ref.notification_manager.send(
                        f"⚠ Audit diario: {len(critical)} hallazgo(s) CRÍTICO(S)",
                        level="critical", scan_id=scan_id,
                    )
                comp = await db.get_comparison(scan_id)
                new_crit = [f for f in comp.get("new", []) if f.get("severity") == "critical"]
                if new_crit:
                    await app_ref.notification_manager.send(
                        f"🆕 {len(new_crit)} nuevos hallazgos críticos detectados",
                        level="critical", scan_id=scan_id,
                    )
            except Exception:
                await db.fail_scan(scan_id)
                raise

        s.add(ScheduleEntry(
            name="daily_audit",
            task_fn=_audit,
            hour=getattr(cfg, "audit_hour", 2),
            minute=getattr(cfg, "audit_minute", 0),
        ))

    if getattr(cfg, "malware_enabled", True):
        async def _malware():
            from cyberhound.scanners.malware import MalwareScanner
            db = app_ref.db
            scan_id = await db.create_scan("malware", triggered_by="scheduler")
            try:
                findings = await MalwareScanner.full_scan(cfg=app_ref.cfg)
                findings = await db.filter_suppressed(findings)
                await db.complete_scan(scan_id, findings)
                if findings:
                    crit = [f for f in findings if f.severity == "critical"]
                    await app_ref.notification_manager.send(
                        f"🦠 Malware scan: {len(findings)} hallazgo(s)"
                        + (f" — {len(crit)} CRÍTICOS" if crit else ""),
                        level="critical" if crit else "warning",
                        scan_id=scan_id,
                    )
            except Exception:
                await db.fail_scan(scan_id)
                raise

        s.add(ScheduleEntry(
            name="weekly_malware",
            task_fn=_malware,
            hour=getattr(cfg, "malware_hour", 3),
            minute=getattr(cfg, "malware_minute", 0),
            days=[getattr(cfg, "malware_day", 0)],
        ))

    if getattr(cfg, "network_enabled", True):
        async def _network():
            from cyberhound.scanners.network import NetworkScanner
            from cyberhound.core.database import AssetRecord
            import json as _json
            db = app_ref.db
            scan_id = await db.create_scan("network", triggered_by="scheduler")
            try:
                devices = await NetworkScanner().scan_network(deep=True)
                new_ips = []
                for dev in devices:
                    asset = AssetRecord(
                        ip=dev.ip, mac=dev.mac, hostname=dev.hostname,
                        vendor=dev.vendor, os_name=dev.os_name,
                        open_ports=_json.dumps([
                            {"port": p.port, "service": p.service}
                            for p in dev.open_ports
                        ]),
                        risk_level=dev.risk_level,
                    )
                    if await db.upsert_asset(asset):
                        new_ips.append(dev.ip)
                if new_ips:
                    ips_str = ", ".join(new_ips[:5])
                    extra = f" y {len(new_ips)-5} más" if len(new_ips) > 5 else ""
                    await app_ref.notification_manager.send(
                        f"📡 Nuevo(s) dispositivo(s) en red: {ips_str}{extra}",
                        level="warning", scan_id=scan_id,
                    )
                await db.complete_scan(scan_id, [])
            except Exception:
                await db.fail_scan(scan_id)
                raise

        s.add(ScheduleEntry(
            name="daily_network",
            task_fn=_network,
            hour=getattr(cfg, "network_hour", 4),
            minute=getattr(cfg, "network_minute", 0),
        ))

    return s
