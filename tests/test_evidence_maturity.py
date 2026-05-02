"""Tests for ``fedramp20x.evidence_maturity``."""

from __future__ import annotations

from fedramp20x.evidence_maturity import (
    compute_ksi_automation_score,
    compute_ksi_evidence_posture,
    compute_package_evidence_maturity_summary,
    infer_criteria_results_from_ksi_result,
    maturity_gaps_for_package,
    score_evidence_source,
)
from fedramp20x.evidence_registry import EvidenceRegistry
from fedramp20x.ksi_catalog import KsiCatalog
from fedramp20x.evidence_registry import EvidenceSource
from fedramp20x.ksi_catalog import Ksi, LegacyControls, ReportingSections


def _src(
    *,
    sid: str = "s1",
    cm: str = "manual",
    fq: str = "manual",
    fmt: str = "markdown",
    cat: str = "inventory",
    collector: str | None = None,
    name: str = "N",
) -> EvidenceSource:
    return EvidenceSource(
        id=sid,
        name=name,
        category=cat,  # type: ignore[arg-type]
        collection_method=cm,  # type: ignore[arg-type]
        collector=collector,
        frequency=fq,  # type: ignore[arg-type]
        owner="o",
        evidence_format=fmt,  # type: ignore[arg-type]
    )


def test_score_evidence_source_manual_narrative_vs_artifact() -> None:
    assert score_evidence_source(_src(cm="manual", fmt="markdown")) == 1
    assert score_evidence_source(_src(cm="manual", fmt="pdf")) == 2
    assert score_evidence_source(_src(cm="manual", fmt="screenshot")) == 2


def test_score_evidence_source_structured_export() -> None:
    assert score_evidence_source(_src(cm="file", fmt="csv")) == 3
    assert score_evidence_source(_src(cm="manual", fmt="json")) == 3


def test_score_evidence_source_api_scheduled_vs_continuous() -> None:
    assert score_evidence_source(_src(cm="api", fq="daily", fmt="json", collector="http://x")) == 4
    assert score_evidence_source(_src(cm="api", fq="continuous", fmt="json", collector="http://x")) == 5
    assert score_evidence_source(_src(cm="hybrid", fq="event_driven", fmt="json", collector="http://x")) == 5


def _ksi(
    *,
    kid: str = "K-1",
    mode: str = "automated",
    evidence: list[str] | None = None,
    criteria: list[dict] | None = None,
) -> Ksi:
    return Ksi(
        ksi_id=kid,
        theme="t",
        title="T",
        objective="o",
        legacy_controls=LegacyControls(rev4=["AC-2"], rev5=["AC-2"]),
        validation_mode=mode,  # type: ignore[arg-type]
        automation_target=True,
        evidence_sources=evidence or [],
        pass_fail_criteria=criteria
        or [
            {
                "criteria_id": "C1",
                "description": "d",
                "validation_type": "automated",
                "severity_if_failed": "medium",
            }
        ],
        reporting_sections=ReportingSections(),
    )


def test_compute_ksi_cap_manual() -> None:
    reg = {"api1": _src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")}
    k = _ksi(mode="manual", evidence=["api1"])
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    assert compute_ksi_automation_score(k, reg, crit) == 2


def test_compute_ksi_cap_hybrid_at_four() -> None:
    reg = {"api1": _src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")}
    k = _ksi(mode="hybrid", evidence=["api1"])
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    assert compute_ksi_automation_score(k, reg, crit) == 4


def test_compute_ksi_missing_required_caps_two() -> None:
    reg = {"api1": _src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")}
    criteria = [
        {
            "criteria_id": "C1",
            "description": "d",
            "validation_type": "automated",
            "severity_if_failed": "medium",
            "evidence_required": ["missing"],
        }
    ]
    k = _ksi(evidence=["api1"], criteria=criteria)
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    assert compute_ksi_automation_score(k, reg, crit) == 2


def test_compute_ksi_score_five_needs_continuous_and_alerting() -> None:
    reg = {
        "logs": _src(sid="logs", cm="api", fq="continuous", fmt="json", collector="https://logs.example", cat="logging"),
        "ticketing": _src(
            sid="ticketing",
            name="Alert routing",
            cm="api",
            fq="daily",
            fmt="json",
            collector="https://ticketing.example",
            cat="incident_response",
        ),
    }
    k = _ksi(evidence=["logs", "ticketing"])
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    assert compute_ksi_automation_score(k, reg, crit) == 5


def test_compute_ksi_automated_four_without_alerting_continuous_pair() -> None:
    reg = {"api1": _src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")}
    k = _ksi(evidence=["api1"])
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    assert compute_ksi_automation_score(k, reg, crit) == 4


def test_criteria_not_evaluated_blocks_four() -> None:
    reg = {"api1": _src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")}
    k = _ksi(evidence=["api1"])
    crit = {"C1": {"criteria_id": "C1", "evaluated": False}}
    assert compute_ksi_automation_score(k, reg, crit) == 3


def test_maturity_gaps_for_package_lists_below_four() -> None:
    pkg = {
        "ksi_catalog": [
            {
                "ksi_id": "K-A",
                "theme": "t",
                "title": "T",
                "objective": "o",
                "legacy_controls": {"rev4": ["AC-1"], "rev5": ["AC-1"]},
                "validation_mode": "manual",
                "automation_target": False,
                "evidence_sources": [],
                "pass_fail_criteria": [
                    {
                        "criteria_id": "C1",
                        "description": "d",
                        "validation_type": "manual",
                        "severity_if_failed": "low",
                    }
                ],
            }
        ],
        "evidence_source_registry": {"sources": []},
        "ksi_validation_results": [{"ksi_id": "K-A", "status": "PASS", "summary": "x"}],
    }
    gaps = maturity_gaps_for_package(pkg)
    assert len(gaps) == 1
    assert gaps[0][0] == "K-A"
    assert gaps[0][1] < 4
    assert "[Manual or file-primary evidence" in gaps[0][2] or "manual" in gaps[0][2].lower()


def test_compute_ksi_evidence_posture_missing_is_not_manual_path() -> None:
    reg = {"api1": _src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")}
    criteria = [
        {
            "criteria_id": "C1",
            "description": "d",
            "validation_type": "automated",
            "severity_if_failed": "medium",
            "evidence_required": ["not_in_registry"],
        }
    ]
    k = _ksi(evidence=["api1"], criteria=criteria)
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    p = compute_ksi_evidence_posture(k, reg, crit)
    assert p["missing_required_evidence"] is True
    assert p["relies_on_manual_or_file_primary_evidence"] is False


def test_compute_ksi_evidence_posture_registered_low_maturity_is_manual_primary_path() -> None:
    reg = {"nar": _src(sid="nar", cm="manual", fmt="markdown", name="policy doc")}
    criteria = [
        {
            "criteria_id": "C1",
            "description": "d",
            "validation_type": "automated",
            "severity_if_failed": "medium",
            "evidence_required": ["nar"],
        }
    ]
    k = _ksi(mode="automated", evidence=[], criteria=criteria)
    crit = infer_criteria_results_from_ksi_result(k, {"status": "PASS"})
    p = compute_ksi_evidence_posture(k, reg, crit)
    assert p["missing_required_evidence"] is False
    assert p["relies_on_manual_or_file_primary_evidence"] is True


def test_package_maturity_summary_has_mode_and_gap_counts() -> None:
    reg = EvidenceRegistry(
        sources=[_src(sid="api1", cm="api", fq="daily", fmt="json", collector="u")]
    )
    crit_base = [
        {
            "criteria_id": "C1",
            "description": "d",
            "validation_type": "automated",
            "severity_if_failed": "medium",
            "evidence_required": ["api1"],
        }
    ]
    k_manual = _ksi(kid="KM", mode="manual", evidence=["api1"], criteria=crit_base)
    k_hybrid = _ksi(kid="KH", mode="hybrid", evidence=["api1"], criteria=crit_base)
    k_auto = _ksi(kid="KA", mode="automated", evidence=["api1"], criteria=crit_base)
    crit_gap = [
        {
            "criteria_id": "C1",
            "description": "d",
            "validation_type": "automated",
            "severity_if_failed": "medium",
            "evidence_required": ["missing_id"],
        }
    ]
    k_gap = _ksi(kid="KG", mode="automated", evidence=["api1"], criteria=crit_gap)
    cat = KsiCatalog(catalog=[k_manual, k_hybrid, k_auto, k_gap])
    results = [
        {"ksi_id": "KM", "status": "PASS"},
        {"ksi_id": "KH", "status": "PASS"},
        {"ksi_id": "KA", "status": "PASS"},
        {"ksi_id": "KG", "status": "PASS"},
    ]
    s = compute_package_evidence_maturity_summary(cat, reg, results)
    assert s["ksi_manual_mode_count"] == 1
    assert s["ksi_hybrid_mode_count"] == 1
    assert s["ksi_automated_mode_count"] == 2
    assert s["ksis_missing_required_evidence"] == 1
    assert "KG" in s["ksi_ids_missing_required_evidence"]
    assert isinstance(s["automation_percentage"], float)
