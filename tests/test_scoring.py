"""Tests del motor de scoring contextual."""
import pytest

from cyberhound.core.models import Finding
from cyberhound.core.scoring import (
    ACCUMULATION_DECAY, AUTO_FIX_REDUCTION, BASE_PENALTY,
    CATEGORY_WEIGHTS, ScoreResult, ScoringContext, compute_score,
)


def f(id="test", severity="high", category="ssh", auto_fix=False):
    return Finding(
        id=id, category=category, severity=severity,
        title="Test", description="", remediation="",
        auto_fix=auto_fix,
    )


class TestScoringContext:

    def test_default_multiplier_is_one(self):
        ctx = ScoringContext()
        assert ctx.exposure_multiplier == 1.0

    def test_internet_facing_increases_multiplier(self):
        ctx = ScoringContext(internet_facing=True)
        assert ctx.exposure_multiplier > 1.0

    def test_web_server_increases_multiplier(self):
        ctx = ScoringContext(is_web_server=True)
        assert ctx.exposure_multiplier > 1.0

    def test_combined_exposure_caps_at_2x(self):
        ctx = ScoringContext(
            internet_facing=True, is_web_server=True,
            is_container=True, open_port_count=20,
        )
        assert ctx.exposure_multiplier <= 2.0

    def test_inferred_from_findings(self):
        findings = [
            f(id="ssh_cve_test", severity="critical", category="ssh/cve"),
        ]
        ctx = ScoringContext.from_findings(findings)
        assert ctx.internet_facing is True  # CVE SSH implica exposición

    def test_neutral_context_no_exposure(self):
        ctx = ScoringContext.from_findings([f(category="updates")])
        assert ctx.exposure_multiplier == 1.0


class TestComputeScore:

    def test_perfect_score_no_findings(self):
        result = compute_score([])
        assert result.score == 100

    def test_score_decreases_with_findings(self):
        r_none = compute_score([])
        r_high = compute_score([f(severity="high")])
        assert r_high.score < r_none.score

    def test_critical_penalizes_more_than_high(self):
        r_critical = compute_score([f(severity="critical")])
        r_high     = compute_score([f(severity="high")])
        assert r_critical.score < r_high.score

    def test_info_findings_dont_reduce_score(self):
        r_none = compute_score([])
        r_info = compute_score([f(severity="info") for _ in range(10)])
        assert r_info.score == r_none.score

    def test_auto_fix_reduces_penalty(self):
        r_no_fix  = compute_score([f(severity="high", auto_fix=False)])
        r_has_fix = compute_score([f(severity="high", auto_fix=True)])
        assert r_has_fix.score > r_no_fix.score

    def test_high_weight_category_penalizes_more(self):
        r_ssh     = compute_score([f(severity="high", category="ssh")])
        r_updates = compute_score([f(severity="high", category="updates")])
        assert r_ssh.score < r_updates.score  # ssh weight > updates weight

    def test_accumulation_decay(self):
        """El 10º finding del mismo tipo pesa menos que el 1º."""
        # Usar severidad high con categoría filesystem para penalización visible
        one_finding  = compute_score([f(severity="high", category="filesystem")])
        ten_findings = compute_score([
            f(id=f"f{i}", severity="high", category="filesystem")
            for i in range(10)
        ])
        delta_one = 100 - one_finding.score
        delta_ten = 100 - ten_findings.score
        # Con 10 findings siempre hay más penalización
        assert delta_ten > delta_one
        # Pero el decaimiento evita que sea lineal: no es 10x la penalización
        # (si fuera lineal, delta_ten == delta_one * 10; con decay es menos)
        # Con DECAY=0.8: sum = 1+0.8+0.64+... ≈ 4.46x, no 10x
        assert delta_ten < delta_one * 10 or delta_one == 0

    def test_score_never_below_zero(self):
        many_criticals = [f(id=f"c{i}", severity="critical") for i in range(20)]
        result = compute_score(many_criticals)
        assert result.score >= 0

    def test_score_never_above_100(self):
        result = compute_score([])
        assert result.score <= 100

    def test_internet_facing_context_lowers_score(self):
        findings = [f(severity="high")]
        r_internal = compute_score(findings, ScoringContext(internet_facing=False))
        r_external = compute_score(findings, ScoringContext(internet_facing=True))
        assert r_external.score < r_internal.score

    def test_docker_escape_has_highest_weight(self):
        r_escape  = compute_score([f(severity="high", category="docker/escape")])
        r_updates = compute_score([f(severity="high", category="updates")])
        assert r_escape.score < r_updates.score

    def test_grade_a_for_high_score(self):
        result = compute_score([])
        assert result.grade == "A"

    def test_grade_f_for_many_criticals(self):
        findings = [f(id=f"c{i}", severity="critical") for i in range(5)]
        result = compute_score(findings)
        assert result.grade in ("D", "F")

    def test_grade_labels_present(self):
        result = compute_score([])
        assert result.grade_label  # no vacío

    def test_bonus_for_no_ssh_findings(self):
        """Sistema sin findings SSH recibe bonus."""
        r_with_ssh    = compute_score([f(severity="medium", category="ssh")])
        r_without_ssh = compute_score([f(severity="medium", category="updates")])
        # El bonus hace que r_without_ssh >= r_with_ssh incluso con el mismo nº de findings
        assert r_without_ssh.score >= r_with_ssh.score

    def test_to_dict_contains_required_keys(self):
        result = compute_score([f(severity="high")])
        d = result.to_dict()
        assert "score" in d
        assert "grade" in d
        assert "grade_label" in d
        assert "exposure_multiplier" in d
        assert "breakdown_top10" in d

    def test_breakdown_sorted_by_penalty(self):
        findings = [
            f(id="crit", severity="critical", category="ssh"),
            f(id="low",  severity="low",      category="updates"),
        ]
        result = compute_score(findings)
        breakdown = result.to_dict()["breakdown_top10"]
        if len(breakdown) >= 2:
            assert breakdown[0]["final_penalty"] >= breakdown[1]["final_penalty"]

    def test_multiple_categories_tracked_independently(self):
        """El decaimiento se aplica por categoría, no globalmente."""
        findings = [
            f(id="ssh1", severity="high", category="ssh"),
            f(id="fw1",  severity="high", category="firewall"),  # categoría diferente
        ]
        result = compute_score(findings)
        # Ambos deben tener decay=1.0 (primeros de su categoría)
        decays = {b["finding_id"]: b["decay"] for b in result.breakdown}
        assert decays.get("ssh1", 0) == 1.0
        assert decays.get("fw1",  0) == 1.0

    def test_same_category_second_finding_has_decay(self):
        findings = [
            f(id="ssh1", severity="high", category="ssh"),
            f(id="ssh2", severity="high", category="ssh"),  # mismo tipo
        ]
        result = compute_score(findings)
        decays = {b["finding_id"]: b["decay"] for b in result.breakdown}
        assert decays.get("ssh1") == 1.0
        assert abs(decays.get("ssh2", 0) - ACCUMULATION_DECAY) < 0.01
