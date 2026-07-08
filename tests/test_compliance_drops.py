"""Tests de compliance en tiempo real (detect_compliance_drops): alerta
cuando un hallazgo nuevo tumba un control que antes pasaba y el score de un
marco normativo baja respecto al scan anterior."""
from cyberhound.core.models import Finding
from cyberhound.scanners.compliance import analyze_compliance, detect_compliance_drops


def _finding(category, severity="high", finding_id=None):
    return Finding(
        id=finding_id or f"test_{category}", category=category, severity=severity,
        title=f"Hallazgo de {category}", description="desc", remediation="fix",
    )


class TestDetectComplianceDrops:
    def test_sin_cambios_no_hay_drops(self):
        findings = [_finding("ssh")]
        assert detect_compliance_drops(findings, findings) == []

    def test_nuevo_hallazgo_que_tumba_un_control_produce_drop(self):
        # Antes: sin hallazgos -> todos los controles pasan (100%).
        # Ahora: aparece un hallazgo de ssh -> un control cae en cada framework.
        previous = []
        current = [_finding("ssh")]
        drops = detect_compliance_drops(previous, current)
        assert len(drops) > 0
        frameworks = {d.framework for d in drops}
        # "ssh" tiene controles mapeados en los 4 frameworks -> los 4 deberían bajar.
        assert frameworks == {"ens", "iso27001", "pci-dss", "cis"}
        for d in drops:
            assert d.current_score < d.previous_score
            assert d.delta > 0

    def test_hallazgo_que_desaparece_MEJORA_el_score_y_no_es_drop(self):
        previous = [_finding("ssh")]
        current = []
        assert detect_compliance_drops(previous, current) == []

    def test_mismo_hallazgo_persistente_no_es_drop_cada_dia(self):
        """Un hallazgo que YA estaba ayer y sigue hoy no debe generar alerta
        de nuevo cada día — el score no cambia entre scans si nada cambió."""
        f = _finding("ssh")
        assert detect_compliance_drops([f], [f]) == []

    def test_filtra_por_frameworks_solicitados(self):
        previous = []
        current = [_finding("ssh")]
        drops = detect_compliance_drops(previous, current, frameworks=["ens"])
        assert {d.framework for d in drops} == {"ens"}

    def test_delta_es_la_diferencia_correcta(self):
        previous = []
        current = [_finding("ssh")]
        prev_analysis = analyze_compliance(previous, frameworks=["ens"])
        curr_analysis = analyze_compliance(current, frameworks=["ens"])
        drops = detect_compliance_drops(previous, current, frameworks=["ens"])
        assert len(drops) == 1
        d = drops[0]
        assert d.previous_score == prev_analysis["ens"].score_pct
        assert d.current_score == curr_analysis["ens"].score_pct
        assert d.delta == round(prev_analysis["ens"].score_pct - curr_analysis["ens"].score_pct, 1)

    def test_categoria_sin_controles_mapeados_no_afecta_nada(self):
        previous = []
        current = [_finding("categoria-inventada-sin-mapeo")]
        assert detect_compliance_drops(previous, current) == []
