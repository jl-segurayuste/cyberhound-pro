"""
Modelos de datos centrales de CyberHound.
Separados de la lógica para poder importarlos en cualquier módulo sin dependencias circulares.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def color_ansi(self) -> str:
        return {
            "critical": "\033[91m", "high": "\033[31m",
            "medium": "\033[33m",   "low": "\033[36m", "info": "\033[37m",
        }[self.value]


@dataclass
class Finding:
    id:          str
    category:    str
    severity:    str          # Severity value
    title:       str
    description: str
    remediation: str
    evidence:    str  = ""
    passed:      bool = False
    auto_fix:    bool = False
    file_path:   str  = ""
    line_number: int  = 0
    code_snippet:str  = ""
    # Multi-host: host de origen (vacío = localhost)
    source_host: str  = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        valid = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in valid})

    @property
    def sev(self) -> Severity:
        try:
            return Severity(self.severity)
        except ValueError:
            return Severity.INFO


@dataclass
class HostResult:
    host:       str
    port:       int
    user:       str
    status:     str          # ok | error | unreachable | auth_failed
    findings:   list[Finding] = field(default_factory=list)
    error:      str = ""
    scan_time:  float = 0.0
    os_info:    str = ""
    open_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class ExternalIntel:
    source:    str
    indicator: str
    data:      Any

    def to_dict(self) -> dict:
        return {"source": self.source, "indicator": self.indicator, "data": self.data}


@dataclass
class ScanReport:
    target:          str
    timestamp:       str = field(default_factory=lambda: datetime.now().isoformat())
    local_findings:  list[Finding] = field(default_factory=list)
    external_intel:  list[ExternalIntel] = field(default_factory=list)
    host_results:    list[HostResult] = field(default_factory=list)
    statistics:      dict[str, int] = field(default_factory=dict)

    def compute_stats(self) -> None:
        counts: dict[str, int] = {}
        for f in self.local_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        self.statistics = counts

    def to_dict(self) -> dict:
        self.compute_stats()
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "statistics": self.statistics,
            "local_findings": [f.to_dict() for f in self.local_findings],
            "external_intel": [i.to_dict() for i in self.external_intel],
            "host_results": [h.to_dict() for h in self.host_results],
        }
