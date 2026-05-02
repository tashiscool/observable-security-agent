"""Executive markdown bundle (KPIs, readiness, risks, automation)."""

from __future__ import annotations

from pathlib import Path

from fedramp20x.report_builder import (
    AUTHORIZATION_READINESS,
    EXECUTIVE_SUMMARY,
    MAJOR_RISKS,
    SECURITY_POSTURE_DASHBOARD,
    write_executive_report,
)

from tests.test_assessor_report_bundle import _cat_row, _minimal_package


def test_executive_includes_automation_percentage(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-A", title="A"), _cat_row("KSI-B", title="B")]
    catalog[0]["automation_target"] = True
    catalog[1]["automation_target"] = False
    results = [
        {"ksi_id": "KSI-A", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []},
        {"ksi_id": "KSI-B", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []},
    ]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    primary = tmp_path / "reports" / "executive" / EXECUTIVE_SUMMARY
    write_executive_report(primary, pkg)
    dash = (primary.parent / SECURITY_POSTURE_DASHBOARD).read_text(encoding="utf-8")
    assert "**50.0%**" in dash or "| **50.0%**" in dash or "50.0%" in dash
    summary = (primary.parent / EXECUTIVE_SUMMARY).read_text(encoding="utf-8")
    assert "50.0%" in summary


def test_executive_includes_top_risks(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "FAIL", "summary": "bad", "linked_eval_ids": [], "evidence_refs": []}]
    findings = [
        {
            "finding_id": "FIND-H",
            "severity": "high",
            "title": "Scanner coverage gap",
            "description": "No evidence of full scanner scope for prod asset class.",
            "risk_statement": "Audit exposure if vulnerabilities are undetected in production.",
            "linked_ksi_ids": ["KSI-1"],
            "status": "open",
        }
    ]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=findings,
        poam_items=[
            {
                "poam_id": "P1",
                "finding_id": "FIND-H",
                "title": "Remediate coverage",
                "risk_owner": "CISO",
                "target_completion_date": "2026-12-31",
                "customer_impact": "Delayed ATO if unresolved.",
                "remediation_plan": [{"step": 1, "owner": "VM team", "due_date": "2026-06-01", "description": "Expand scope export"}],
                "status": "Open",
            }
        ],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"] = {
        "findings_machine": 1,
        "findings_human_reports": 1,
        "poam_items_machine": 1,
        "ksi_results": 1,
    }
    primary = tmp_path / "executive-summary.md"
    write_executive_report(primary, pkg)
    risks = (primary.parent / MAJOR_RISKS).read_text(encoding="utf-8")
    assert "FIND-H" in risks
    assert "Scanner coverage gap" in risks
    assert "Audit exposure" in risks or "audit exposure" in risks.lower()


def test_executive_includes_readiness_decision(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "FAIL", "summary": "x", "linked_eval_ids": [], "evidence_refs": []}]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"]["ksi_results"] = 1
    primary = tmp_path / "e" / EXECUTIVE_SUMMARY
    write_executive_report(primary, pkg)
    auth = (primary.parent / AUTHORIZATION_READINESS).read_text(encoding="utf-8")
    summ = (primary.parent / EXECUTIVE_SUMMARY).read_text(encoding="utf-8")
    assert "**Verdict:** `not_ready`" in auth
    assert "**`not_ready`**" in summ or "`not_ready`" in summ


def test_executive_bundle_files_exist(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    d = tmp_path / "reports" / "executive"
    primary = d / "executive-summary.md"
    write_executive_report(primary, pkg)
    for name in (
        EXECUTIVE_SUMMARY,
        SECURITY_POSTURE_DASHBOARD,
        AUTHORIZATION_READINESS,
        MAJOR_RISKS,
    ):
        assert (d / name).is_file(), name
