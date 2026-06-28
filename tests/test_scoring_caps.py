"""El volumen de hallazgos de baja criticidad no debe hundir el score:
tope de penalización por severidad (rendimientos decrecientes)."""
from cyberhound.core.models import Finding
from cyberhound.core.scoring import SEVERITY_PENALTY_CAP, compute_score


def _mk(sev, cat, i, fix=True):
    return Finding(id=f"{cat}_{sev}_{i}", category=cat, severity=sev,
                   title="x", description="d", remediation="r", auto_fix=fix)


def test_many_lows_do_not_floor_score():
    fs = [_mk("low", "logging", i) for i in range(60)]
    assert compute_score(fs).score >= 85


def test_many_mediums_capped():
    fs = [_mk("medium", "filesystem", i) for i in range(60)]
    # 60 medios no pueden penalizar más que el tope (+ algo de exposición)
    assert compute_score(fs).score >= 65


def test_no_high_severity_is_not_critical_grade():
    # Sin críticos ni altos, solo medios/bajos → no debería ser "Crítico"
    fs = [_mk("medium", "filesystem", i) for i in range(15)] + \
         [_mk("low", "logging", i) for i in range(30)]
    assert compute_score(fs).grade != "F"


def test_critical_still_dominates():
    crit = compute_score([_mk("critical", "ssh/cve", 0, fix=False)]).score
    lows = compute_score([_mk("low", "logging", i) for i in range(60)]).score
    assert crit < lows  # un crítico pesa más que 60 bajos


def test_caps_are_ordered():
    assert (SEVERITY_PENALTY_CAP["critical"] > SEVERITY_PENALTY_CAP["high"]
            > SEVERITY_PENALTY_CAP["medium"] > SEVERITY_PENALTY_CAP["low"])
