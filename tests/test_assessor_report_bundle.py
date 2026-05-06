"""Assessor markdown bundle (KSI coverage, findings, evidence index, reconciliation counts)."""

from __future__ import annotations

from pathlib import Path

from fedramp20x.report_builder import (
    ASSESSOR_SUMMARY,
    EVIDENCE_INDEX,
    KSI_BY_KSI,
    write_assessor_report,
)


def _minimal_package(
    *,
    ksi_catalog: list[dict],
    ksi_results: list[dict],
    findings: list[dict],
    poam_items: list[dict],
    evidence_links: list[dict],
) -> dict:
    return {
        "schema_version": "1.0",
        "package_metadata": {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "generator_id": "test",
            "assessment_output_uri": "/tmp/assessment-output",
        },
        "system_boundary": {"system_id": "S1", "short_name": "sys"},
        "authorization_scope": {
            "impact_level": "moderate",
            "authorization_boundary_id": "AB-1",
            "deployment_model": "customer_managed_cloud",
            "in_scope_services": [{"category": "compute_workloads"}],
            "out_of_scope": [
                {
                    "category": "physical_facilities",
                    "rationale": "Inherited from cloud service provider per shared responsibility.",
                }
            ],
        },
        "evidence_source_registry": {
            "schema_version": "1.0",
            "sources": [
                {
                    "id": "src-a",
                    "name": "Source A",
                    "category": "logging",
                    "collection_method": "api",
                    "frequency": "continuous",
                    "owner": "o",
                    "evidence_format": "json",
                    "automation_score": 4,
                    "limitations": ["API scope"],
                }
            ],
        },
        "ksi_catalog": ksi_catalog,
        "control_crosswalk": {"rev4_to_rev5": [], "rev5_to_20x_ksi": []},
        "ksi_validation_results": ksi_results,
        "findings": findings,
        "poam_items": poam_items,
        "evidence_links": evidence_links,
        "reconciliation_summary": {
            "parity_status": "aligned",
            "counts": {
                "findings_machine": len(findings),
                "findings_human_reports": len(findings),
                "poam_items_machine": len(poam_items),
                "ksi_results": len(ksi_results),
            },
            "human_report_manifest": [],
            "package_sha256": "abc123",
            "notes": [],
        },
    }


def _cat_row(kid: str, title: str = "T", theme: str = "Th") -> dict:
    return {
        "ksi_id": kid,
        "theme": theme,
        "title": title,
        "objective": "Objective text.",
        "legacy_controls": {"rev4": ["AC-1"], "rev5": ["AC-1"]},
        "validation_mode": "hybrid",
        "automation_target": True,
        "evidence_sources": ["src-a"],
        "pass_fail_criteria": [
            {
                "criteria_id": f"{kid}-C1",
                "description": "Criterion one.",
                "validation_type": "automated",
                "expected_result": "Pass",
                "severity_if_failed": "medium",
                "eval_refs": [],
                "evidence_required": ["src-a"],
            }
        ],
    }


def test_every_ksi_in_assessor_ksi_by_ksi(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-1"), _cat_row("KSI-2", title="Second")]
    results = [
        {"ksi_id": "KSI-1", "status": "PASS", "summary": "ok", "linked_eval_ids": ["E1"], "evidence_refs": []},
        {"ksi_id": "KSI-2", "status": "PASS", "summary": "ok", "linked_eval_ids": [], "evidence_refs": []},
    ]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    primary = tmp_path / "reports" / "assessor" / ASSESSOR_SUMMARY
    write_assessor_report(primary, pkg)
    ksi_md = (primary.parent / KSI_BY_KSI).read_text(encoding="utf-8")
    assert "`KSI-1`" in ksi_md
    assert "`KSI-2`" in ksi_md


def test_failed_ksi_includes_finding_and_poam_ref(tmp_path: Path) -> None:
    catalog = [_cat_row("KSI-FAIL")]
    results = [
        {
            "ksi_id": "KSI-FAIL",
            "status": "FAIL",
            "summary": "Rollup fail.",
            "linked_eval_ids": ["E1"],
            "evidence_refs": [{"artifact": "eval_results.json", "role": "primary"}],
        }
    ]
    findings = [
        {
            "finding_id": "FIND-1",
            "severity": "high",
            "priority": "critical",
            "estimated_effort": "1-3 days",
            "title": "Gap",
            "description": "Evidence gap described.",
            "linked_ksi_ids": ["KSI-FAIL"],
            "poam_id": "POAM-99",
            "nist_control_refs": ["AC-1"],
            "assessor_workpaper": {
                "current_state": "Current evidence is incomplete.",
                "target_state": "Evidence is complete and retestable.",
                "remediation_steps": ["Collect evidence", "Re-run validation"],
                "estimated_effort": "1-3 days",
                "priority": "critical",
            },
        }
    ]
    poam = [
        {
            "poam_id": "POAM-99",
            "finding_id": "FIND-1",
            "title": "Fix",
            "severity": "high",
            "source_ksi_ids": ["KSI-FAIL"],
            "source_controls": ["AC-1"],
            "remediation_plan": [],
        }
    ]
    pkg = _minimal_package(
        ksi_catalog=catalog,
        ksi_results=results,
        findings=findings,
        poam_items=poam,
        evidence_links=[],
    )
    primary = tmp_path / "a" / "assessor-summary.md"
    write_assessor_report(primary, pkg)
    ksi_md = (primary.parent / KSI_BY_KSI).read_text(encoding="utf-8")
    assert "FAIL" in ksi_md
    assert "FIND-1" in ksi_md
    assert "POAM-99" in ksi_md
    assert "Assessor workpaper" in ksi_md
    assert "Current evidence is incomplete" in ksi_md
    summary = (primary.parent / ASSESSOR_SUMMARY).read_text(encoding="utf-8")
    assert "Priority" in summary
    assert "critical" in summary


def test_evidence_paths_in_index(tmp_path: Path) -> None:
    pkg = _minimal_package(
        ksi_catalog=[_cat_row("KSI-1")],
        ksi_results=[{"ksi_id": "KSI-1", "status": "PASS", "summary": "s", "linked_eval_ids": [], "evidence_refs": []}],
        findings=[],
        poam_items=[],
        evidence_links=[{"link_id": "L1", "from_ref": {"ref_type": "a", "ref_id": "1"}, "to_ref": {"ref_type": "b", "ref_id": "2"}, "relationship": "r", "artifact_uri": "evidence_graph.json"}],
    )
    primary = tmp_path / "assessor-summary.md"
    write_assessor_report(primary, pkg)
    idx = (primary.parent / EVIDENCE_INDEX).read_text(encoding="utf-8")
    assert "fedramp20x-package.json" in idx
    assert "/tmp/assessment-output" in idx
    assert "evidence_graph.json" in idx
    assert "abc123" in idx


def test_report_counts_match_reconciliation(tmp_path: Path) -> None:
    findings = [
        {
            "finding_id": "F1",
            "severity": "low",
            "title": "t",
            "description": "d",
            "linked_ksi_ids": ["KSI-1"],
        }
    ]
    poam = [{"poam_id": "P1", "finding_id": "F1", "source_ksi_ids": ["KSI-1"]}]
    pkg = _minimal_package(
        ksi_catalog=[_cat_row("KSI-1")],
        ksi_results=[{"ksi_id": "KSI-1", "status": "PARTIAL", "summary": "s", "linked_eval_ids": [], "evidence_refs": []}],
        findings=findings,
        poam_items=poam,
        evidence_links=[],
    )
    primary = tmp_path / "assessor-summary.md"
    write_assessor_report(primary, pkg)
    summary = (primary.parent / ASSESSOR_SUMMARY).read_text(encoding="utf-8")
    assert "| KSI results | 1 | `1` |" in summary
    assert "| Findings | 1 | `1` |" in summary
    assert "| POA&M items | 1 | `1` |" in summary


def test_assessor_bundle_files_exist(tmp_path: Path) -> None:
    pkg = _minimal_package(
        ksi_catalog=[_cat_row("KSI-1")],
        ksi_results=[{"ksi_id": "KSI-1", "status": "PASS", "summary": "s", "linked_eval_ids": [], "evidence_refs": []}],
        findings=[],
        poam_items=[],
        evidence_links=[],
    )
    d = tmp_path / "reports" / "assessor"
    primary = d / "assessor-summary.md"
    write_assessor_report(primary, pkg)
    for name in (
        "assessor-summary.md",
        "ksi-by-ksi-assessment.md",
        "evidence-index.md",
        "validation-methodology.md",
        "exceptions-and-manual-evidence.md",
        "poam.md",
    ):
        assert (d / name).is_file(), name
