"""Deep reconciliation (REC-001 … REC-010) vs generated reports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fedramp20x.reconciliation import deep_reconcile, write_deep_reconciliation_outputs
from fedramp20x.report_builder import (
    AO_RISK_BRIEF,
    ASSESSOR_SUMMARY,
    EXECUTIVE_SUMMARY,
    write_agency_ao_report,
    write_assessor_report,
    write_executive_report,
)

from tests.test_assessor_report_bundle import _cat_row, _minimal_package

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def _write_package_and_reports(pkg_dir: Path, package: dict) -> None:
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "fedramp20x-package.json").write_text(json.dumps(package, indent=2), encoding="utf-8")
    write_assessor_report(pkg_dir / "reports" / "assessor" / ASSESSOR_SUMMARY, package)
    write_executive_report(pkg_dir / "reports" / "executive" / EXECUTIVE_SUMMARY, package)
    write_agency_ao_report(pkg_dir / "reports" / "agency-ao" / AO_RISK_BRIEF, package)


def test_valid_package_reconciles(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["human_report_manifest"] = [
        {"path": "reports/assessor/assessor-summary.md", "role": "assessor"},
        {"path": "reports/executive/executive-summary.md", "role": "executive"},
        {"path": "reports/agency-ao/ao-risk-brief.md", "role": "agency_ao"},
    ]
    pkg_dir = tmp_path / "pkg"
    _write_package_and_reports(pkg_dir, pkg)
    doc = deep_reconcile(
        package=pkg,
        machine_package_path=pkg_dir / "fedramp20x-package.json",
        report_root=pkg_dir,
    )
    assert doc["overall_status"] == "pass"
    assert all(c["status"] == "pass" for c in doc["checks"])
    write_deep_reconciliation_outputs(doc, output_root=pkg_dir)
    assert (pkg_dir / "evidence" / "validation-results" / "reconciliation.json").is_file()
    assert (pkg_dir / "reports" / "assessor" / "reconciliation-summary.md").is_file()


def test_altered_executive_count_fails_reconciliation(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["human_report_manifest"] = [
        {"path": "reports/assessor/assessor-summary.md", "role": "assessor"},
        {"path": "reports/executive/executive-summary.md", "role": "executive"},
        {"path": "reports/agency-ao/ao-risk-brief.md", "role": "agency_ao"},
    ]
    pkg_dir = tmp_path / "pkg"
    _write_package_and_reports(pkg_dir, pkg)
    es = pkg_dir / "reports" / "executive" / EXECUTIVE_SUMMARY
    text = es.read_text(encoding="utf-8")
    text = text.replace("**1** KSIs tracked", "**99** KSIs tracked", 1)
    es.write_text(text, encoding="utf-8")
    doc = deep_reconcile(
        package=pkg,
        machine_package_path=pkg_dir / "fedramp20x-package.json",
        report_root=pkg_dir,
    )
    rec3 = next(c for c in doc["checks"] if c["id"] == "REC-003")
    assert rec3["status"] == "fail"
    assert doc["overall_status"] == "fail"


def test_missing_poam_ref_fails_reconciliation(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}]
    findings = [
        {
            "finding_id": "F-OPEN",
            "severity": "medium",
            "title": "t",
            "description": "d",
            "status": "open",
            "linked_ksi_ids": ["KSI-1"],
        }
    ]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=findings,
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["counts"]["findings_machine"] = 1
    pkg["reconciliation_summary"]["human_report_manifest"] = [
        {"path": "reports/assessor/assessor-summary.md", "role": "assessor"},
        {"path": "reports/executive/executive-summary.md", "role": "executive"},
        {"path": "reports/agency-ao/ao-risk-brief.md", "role": "agency_ao"},
    ]
    pkg_dir = tmp_path / "pkg"
    _write_package_and_reports(pkg_dir, pkg)
    doc = deep_reconcile(
        package=pkg,
        machine_package_path=pkg_dir / "fedramp20x-package.json",
        report_root=pkg_dir,
    )
    rec5 = next(c for c in doc["checks"] if c["id"] == "REC-005")
    assert rec5["status"] == "fail"


def test_reconcile_reports_cli_exit_code(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1")]
    results = [{"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []}]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    pkg["reconciliation_summary"]["human_report_manifest"] = [
        {"path": "reports/assessor/assessor-summary.md", "role": "assessor"},
        {"path": "reports/executive/executive-summary.md", "role": "executive"},
        {"path": "reports/agency-ao/ao-risk-brief.md", "role": "agency_ao"},
    ]
    pkg_dir = tmp_path / "pkg"
    _write_package_and_reports(pkg_dir, pkg)
    r = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "reconcile-reports",
            "--package-output",
            str(pkg_dir),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr + r.stdout
