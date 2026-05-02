"""Agency AO markdown bundle."""

from __future__ import annotations

from pathlib import Path

from fedramp20x.report_builder import (
    AO_RISK_BRIEF,
    AUTHORIZATION_DECISION_SUPPORT,
    CUSTOMER_RESP_MATRIX,
    INHERITED_CONTROLS_SUMMARY,
    RESIDUAL_RISK_REGISTER,
    write_agency_ao_report,
)

from tests.test_assessor_report_bundle import _cat_row, _minimal_package


def test_ao_report_includes_residual_risk(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1", title="One", theme="Identity")]
    results = [{"ksi_id": "KSI-1", "status": "PARTIAL", "summary": "gap", "linked_eval_ids": [], "evidence_refs": []}]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"]["ksi_results"] = 1
    p = tmp_path / "reports" / "agency-ao" / AO_RISK_BRIEF
    write_agency_ao_report(p, pkg)
    reg = (p.parent / RESIDUAL_RISK_REGISTER).read_text(encoding="utf-8")
    assert "Residual risk" in reg or "residual" in reg.lower()
    assert "Identity" in reg
    assert "PARTIAL" in reg


def test_customer_responsibility_matrix_generated(tmp_path: Path) -> None:
    pkg = _minimal_package(
        ksi_catalog=[_cat_row("KSI-1")],
        ksi_results=[{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}],
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"]["ksi_results"] = 1
    p = tmp_path / "ao" / AO_RISK_BRIEF
    write_agency_ao_report(p, pkg)
    mx = (p.parent / CUSTOMER_RESP_MATRIX).read_text(encoding="utf-8")
    assert "Customer responsibility matrix" in mx
    assert "CSP responsibility" in mx
    assert "agency responsibility" in mx.lower()
    assert "compute_workloads" in mx


def test_inherited_controls_summary_generated(tmp_path: Path) -> None:
    pkg = _minimal_package(
        ksi_catalog=[_cat_row("KSI-1")],
        ksi_results=[{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}],
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"]["ksi_results"] = 1
    p = tmp_path / "ao" / AO_RISK_BRIEF
    write_agency_ao_report(p, pkg)
    inh = (p.parent / INHERITED_CONTROLS_SUMMARY).read_text(encoding="utf-8")
    assert "Inherited controls summary" in inh
    assert "physical_facilities" in inh


def test_open_high_findings_in_ao_brief(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    findings = [
        {
            "finding_id": "FH-1",
            "severity": "high",
            "title": "High risk item",
            "description": "d",
            "risk_statement": "Business exposure.",
            "linked_ksi_ids": ["KSI-1"],
            "status": "open",
        }
    ]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=[{"ksi_id": "KSI-1", "status": "PARTIAL", "summary": "s", "linked_eval_ids": [], "evidence_refs": []}],
        findings=findings,
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"] = {"findings_machine": 1, "findings_human_reports": 1, "poam_items_machine": 0, "ksi_results": 1}
    p = tmp_path / "ao" / AO_RISK_BRIEF
    write_agency_ao_report(p, pkg)
    brief = p.read_text(encoding="utf-8")
    assert "FH-1" in brief
    assert "high" in brief.lower()


def test_agency_ao_bundle_files_exist(tmp_path: Path) -> None:
    pkg = _minimal_package(
        ksi_catalog=[_cat_row("KSI-1")],
        ksi_results=[{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}],
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"]["ksi_results"] = 1
    d = tmp_path / "reports" / "agency-ao"
    write_agency_ao_report(d / AO_RISK_BRIEF, pkg)
    for name in (
        AO_RISK_BRIEF,
        AUTHORIZATION_DECISION_SUPPORT,
        RESIDUAL_RISK_REGISTER,
        CUSTOMER_RESP_MATRIX,
        INHERITED_CONTROLS_SUMMARY,
    ):
        assert (d / name).is_file(), name
