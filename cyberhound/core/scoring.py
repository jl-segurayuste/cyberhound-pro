"""
Motor de scoring avanzado para CyberHound Pro.

El scoring básico (100 - penalizaciones fijas) no refleja el riesgo real:
  - Un servidor web expuesto a internet con SSH sin PasswordAuthentication=no
    es MUCHO más peligroso que el mismo problema en un servidor interno.
  - Un finding crítico corregible automáticamente pesa menos que uno sin fix.
  - Acumular 50 hallazgos medium de log permissions es ruido, no riesgo real.

Este módulo implementa un scoring contextual que considera:
  1. Categoría del finding (red, auth, kernel > filesystem, updates)
  2. Superficie de exposición (¿tiene puertos abiertos? ¿está en DMZ?)
  3. Fixabilidad (auto_fix disponible = acción posible)
  4. Acumulación (el décimo finding del mismo tipo pesa menos)
  5. Bonus por buenas prácticas detectadas
"""
from __future__ import annotations

from dataclasses import dataclass, field

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("scoring")


# ── Pesos por categoría ───────────────────────────────────────────────────────
# Escala 1.0 = peso normal, >1.0 = más importante, <1.0 = menos importante

CATEGORY_WEIGHTS: dict[str, float] = {
    # Críticos para seguridad de red
    "ssh":              1.5,
    "firewall":         1.5,
    "network":          1.4,
    "docker/escape":    2.0,   # escape de contenedor = crítico máximo
    "docker/privilege": 1.8,
    # Importantes para integridad del sistema
    "authentication":   1.3,
    "kernel":           1.2,
    "integrity":        1.2,
    "audit":            1.1,
    "sudo":             1.3,
    "ssh/cve":          1.8,   # CVEs en SSH son muy peligrosos
    # Estándar
    "malware/yara":     1.4,
    "malware/hash":     1.5,
    "malware/behavior": 1.3,
    "malware/webshell": 1.4,
    "malware/persistence": 1.3,
    "docker/secrets":   1.2,
    "docker/cve":       1.3,
    # Menos críticos (hygiene)
    "filesystem":       0.8,
    "services":         0.9,
    "updates":          0.7,
    "logging":          0.6,
    "time":             0.5,
    "compliance":       0.4,
    "storage":          0.6,
    "cron":             0.8,
    "mac":              0.7,
    # Código (depende del contexto)
    "code/python/bandit": 0.9,
    "code/shell":       0.8,
    "code/secrets":     1.3,
    "code/javascript":  0.7,
}

# Penalización base por severidad
BASE_PENALTY: dict[str, float] = {
    "critical": 25.0,
    "high":     12.0,
    "medium":    5.0,
    "low":       1.5,
    "info":      0.0,
}

# Reducción por tener fix automático disponible (el riesgo es manejable)
AUTO_FIX_REDUCTION = 0.75   # -25% si hay fix disponible

# Factor de decaimiento por acumulación del mismo tipo
# El 1er finding de un tipo vale 100%, el 2do 80%, el 5to 40%...
ACCUMULATION_DECAY = 0.80

# Tope de penalización TOTAL por nivel de severidad (rendimientos decrecientes).
# Evita que el mero volumen de hallazgos de baja criticidad hunda el score: un
# sistema sin críticos ni altos no debería caer a "Crítico" solo por acumular
# medios/bajos. Los críticos sí pueden, por sí solos, hundir el score.
SEVERITY_PENALTY_CAP: dict[str, float] = {
    "critical": 70.0,
    "high":     24.0,
    "medium":   12.0,
    "low":       6.0,
}


@dataclass
class ScoringContext:
    """
    Contexto del sistema que se está analizando.
    Aumenta o reduce el impacto de los findings según la exposición.
    """
    # Superficie de exposición
    internet_facing: bool = False     # ¿El sistema tiene IP pública o está en DMZ?
    has_open_ports:  bool = False     # ¿Tiene puertos expuestos?
    open_port_count: int  = 0        # Número de puertos abiertos
    is_container:    bool = False     # ¿Es un contenedor Docker?
    is_web_server:   bool = False     # ¿Sirve tráfico HTTP/HTTPS?

    # Factor multiplicador final (calculado automáticamente)
    exposure_multiplier: float = field(init=False, default=1.0)

    def __post_init__(self):
        mult = 1.0
        if self.internet_facing:
            mult *= 1.4   # +40% si está expuesto a internet
        if self.is_web_server:
            mult *= 1.2   # +20% si es web server (superficie de ataque mayor)
        if self.open_port_count > 10:
            mult *= 1.1   # +10% si tiene muchos puertos abiertos
        if self.is_container:
            mult *= 1.1   # +10% en contenedores (impacto potencial mayor)
        self.exposure_multiplier = min(mult, 2.0)  # cap a 2x

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScoringContext:
        """Infiere el contexto a partir de los propios hallazgos."""
        open_ports = 0
        internet_facing = False
        is_web = False

        for f in findings:
            # Si hay servicios escuchando en 0.0.0.0, hay exposición
            if f.category == "network" and "0.0.0.0" in (f.evidence or ""):
                open_ports += 1
            if "svc_listen_all" in f.id:
                open_ports += 1
            # Si hay findings de CVEs SSH o red, probablemente expuesto
            if f.category in ("ssh/cve", "docker/escape"):
                internet_facing = True
            # Si hay webshells o findings de web
            if "webshell" in f.category or "web" in f.id.lower():
                is_web = True

        return cls(
            internet_facing=internet_facing,
            has_open_ports=open_ports > 0,
            open_port_count=open_ports,
            is_web_server=is_web,
        )


def compute_score(
    findings: list[Finding],
    context: ScoringContext | None = None,
) -> ScoreResult:
    """
    Calcula el score de seguridad con ponderación contextual.

    Returns ScoreResult con el score (0-100) y el desglose detallado.
    """
    if context is None:
        context = ScoringContext.from_findings(findings)

    # Contar por categoría para el decaimiento por acumulación
    category_counts: dict[str, int] = {}
    penalty_by_severity: dict[str, float] = {}

    breakdown: list[dict] = []

    for f in findings:
        if f.severity == "info" or f.severity not in BASE_PENALTY:
            continue

        # 1. Penalización base según severidad
        base = BASE_PENALTY[f.severity]

        # 2. Peso por categoría
        cat_weight = CATEGORY_WEIGHTS.get(f.category, 1.0)
        # Buscar por prefijo si no hay match exacto
        if f.category not in CATEGORY_WEIGHTS:
            for cat_prefix, w in CATEGORY_WEIGHTS.items():
                if f.category.startswith(cat_prefix):
                    cat_weight = w
                    break

        # 3. Reducción si hay fix automático
        fix_factor = AUTO_FIX_REDUCTION if f.auto_fix else 1.0

        # 4. Factor de decaimiento por acumulación del mismo tipo
        cat_key = f"{f.category}:{f.severity}"
        count = category_counts.get(cat_key, 0)
        category_counts[cat_key] = count + 1
        decay = ACCUMULATION_DECAY ** count  # 1.0, 0.8, 0.64, 0.51...

        # 5. Factor de exposición del contexto
        exposure = context.exposure_multiplier

        penalty = base * cat_weight * fix_factor * decay * exposure

        penalty_by_severity[f.severity] = penalty_by_severity.get(f.severity, 0.0) + penalty
        breakdown.append({
            "finding_id": f.id,
            "severity": f.severity,
            "category": f.category,
            "base_penalty": round(base, 2),
            "cat_weight": round(cat_weight, 2),
            "fix_factor": round(fix_factor, 2),
            "decay": round(decay, 2),
            "exposure": round(exposure, 2),
            "final_penalty": round(penalty, 2),
        })

    # Tope por severidad: el volumen de un nivel no puede penalizar más de su cap.
    total_penalty = sum(
        min(pen, SEVERITY_PENALTY_CAP.get(sev, pen))
        for sev, pen in penalty_by_severity.items()
    )

    score = max(0, min(100, round(100 - total_penalty)))

    # Bonus por buenas prácticas (hallazgos ausentes = bueno)
    category_set = {f.category for f in findings}
    bonus = 0
    if "firewall" not in category_set:
        bonus += 2   # +2 si el firewall está bien
    if "ssh" not in category_set:
        bonus += 2   # +2 si SSH está bien configurado
    if "authentication" not in category_set:
        bonus += 1   # +1 si auth está bien

    score = min(100, score + bonus)

    # Calcular grade
    if score >= 90:
        grade, grade_label = "A", "Excelente"
    elif score >= 75:
        grade, grade_label = "B", "Bueno"
    elif score >= 60:
        grade, grade_label = "C", "Mejorable"
    elif score >= 40:
        grade, grade_label = "D", "Deficiente"
    else:
        grade, grade_label = "F", "Crítico"

    result = ScoreResult(
        score=score,
        grade=grade,
        grade_label=grade_label,
        total_penalty=round(total_penalty, 2),
        bonus=bonus,
        context=context,
        breakdown=breakdown,
    )

    logger.debug(
        "Score calculado: %d (%s) | penalización=%.1f bonus=%d | "
        "contexto: exposición=%.1fx",
        score, grade, total_penalty, bonus, context.exposure_multiplier,
    )
    return result


@dataclass
class ScoreResult:
    score:         int
    grade:         str          # A, B, C, D, F
    grade_label:   str          # Excelente, Bueno...
    total_penalty: float
    bonus:         int
    context:       ScoringContext
    breakdown:     list[dict]

    def to_dict(self) -> dict:
        return {
            "score":           self.score,
            "grade":           self.grade,
            "grade_label":     self.grade_label,
            "total_penalty":   self.total_penalty,
            "bonus":           self.bonus,
            "exposure_multiplier": round(self.context.exposure_multiplier, 2),
            "internet_facing": self.context.internet_facing,
            "breakdown_top10": sorted(
                self.breakdown, key=lambda x: x["final_penalty"], reverse=True
            )[:10],
        }
