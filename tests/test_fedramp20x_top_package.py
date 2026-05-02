"""Unit tests for ``build_fedramp20x_package`` (top-level FedRAMP 20x package layout)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from fedramp20x.package_builder import (
    Fedramp20xPackageValidationError,
    build_fedramp20x_package,
)

MIN_KSI = """
schema_version: "1.0"
catalog:
  - ksi_id: KSI-AUTO
    theme: t
    title: Automated KSI
    objective: o
    legacy_controls:
      rev4: [AC-2]
      rev5: [AC-2]
    validation_mode: automated
    automation_target: true
    evidence_sources:
      - test_src
    pass_fail_criteria:
      - criteria_id: C1
        description: d
        validation_type: automated
        severity_if_failed: medium
  - ksi_id: KSI-MAN
    theme: t
    title: Manual KSI
    objective: o
    legacy_controls:
      rev4: [AC-3]
      rev5: [AC-3]
    validation_mode: manual
    automation_target: false
    pass_fail_criteria:
      - criteria_id: C2
        description: d
        validation_type: manual
        severity_if_failed: low
"""

EVIDENCE_REG = """
schema_version: "1.0"
sources:
  - id: test_src
    name: Test API collector
    category: inventory
    collection_method: api
    collector: https://example.invalid/metrics
    frequency: daily
    owner: Test Owner
    evidence_format: json
"""


def _write_fixtures(root: Path) -> dict[str, Path]:
    cfg = root / "config"
    cfg.mkdir(parents=True)
    (cfg / "system-boundary.yaml").write_text(
        yaml.safe_dump(
            {
                "system_id": "SYS-1",
                "short_name": "Test System",
                "cloud_provider": "aws",
                "regions": ["us-east-1"],
                "authorization_path": "FedRAMP",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (cfg / "authorization-scope.yaml").write_text(
        yaml.safe_dump(
            {
                "impact_level": "moderate",
                "in_scope_services": ["compute"],
                "out_of_scope": [],
                "minimum_assessment_scope_applied": True,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (cfg / "ksi-catalog.yaml").write_text(MIN_KSI, encoding="utf-8")
    (cfg / "evidence-source-registry.yaml").write_text(EVIDENCE_REG, encoding="utf-8")

    art = root / "assessment"
    art.mkdir(parents=True)
    ksi_results = [
        {
            "ksi_id": "KSI-AUTO",
            "status": "PASS",
            "summary": "ok",
            "linked_eval_ids": [],
            "linked_nist_control_refs": [],
            "evidence_refs": [],
        },
        {
            "ksi_id": "KSI-MAN",
            "status": "PASS",
            "summary": "ok",
            "linked_eval_ids": [],
            "linked_nist_control_refs": [],
            "evidence_refs": [],
        },
    ]
    (art / "ksi_results.json").write_text(json.dumps({"ksi_results": ksi_results}), encoding="utf-8")
    (art / "findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    (art / "poam-items.json").write_text(json.dumps({"poam_items": []}), encoding="utf-8")
    (art / "evidence_graph.json").write_text(json.dumps({"edges": []}), encoding="utf-8")
    (art / "eval_results.json").write_text(json.dumps({"correlation_id": "corr-1"}), encoding="utf-8")

    reports = root / "reports"
    reports.mkdir(parents=True)
    (reports / "assessor.md").write_text("# A", encoding="utf-8")
    (reports / "exec.md").write_text("# E", encoding="utf-8")
    (reports / "ao.md").write_text("# AO", encoding="utf-8")
    (reports / "recon.md").write_text("# R", encoding="utf-8")

    return {
        "system_boundary": cfg / "system-boundary.yaml",
        "authorization_scope": cfg / "authorization-scope.yaml",
        "ksi_catalog": cfg / "ksi-catalog.yaml",
        "evidence_registry": cfg / "evidence-source-registry.yaml",
        "ksi_results": art / "ksi_results.json",
        "findings": art / "findings.json",
        "poam": art / "poam-items.json",
        "graph": art / "evidence_graph.json",
        "eval": art / "eval_results.json",
        "assessor": reports / "assessor.md",
        "executive": reports / "exec.md",
        "ao": reports / "ao.md",
        "recon": reports / "recon.md",
    }


def test_top_package_required_fields_and_paths(tmp_path: Path) -> None:
    paths = _write_fixtures(tmp_path)
    pkg = tmp_path / "package"
    doc = build_fedramp20x_package(
        package_output=pkg,
        system_boundary_path=paths["system_boundary"],
        authorization_scope_path=paths["authorization_scope"],
        ksi_catalog_path=paths["ksi_catalog"],
        ksi_results_path=paths["ksi_results"],
        findings_path=paths["findings"],
        poam_items_path=paths["poam"],
        evidence_graph_path=paths["graph"],
        eval_results_path=paths["eval"],
        evidence_registry_path=paths["evidence_registry"],
        report_paths={
            "assessor_report": paths["assessor"],
            "executive_report": paths["executive"],
            "ao_report": paths["ao"],
            "reconciliation_report": paths["recon"],
        },
        package_id="PKG-TEST",
    )

    for key in (
        "package_id",
        "package_version",
        "generated_at",
        "system",
        "scope",
        "summary",
        "schema",
        "artifacts",
        "integrity",
    ):
        assert key in doc
    assert doc["package_id"] == "PKG-TEST"
    assert doc["system"]["id"] == "SYS-1"
    assert doc["schema"]["name"]
    assert doc["schema"]["version"]
    assert doc["schema"]["uri"]

    assert (pkg / "fedramp20x-package.json").is_file()
    assert (pkg / "fedramp20x-package.yaml").is_file()
    assert (pkg / "manifest.json").is_file()
    assert (pkg / "checksums.sha256").is_file()

    for rel in (
        doc["artifacts"]["ksi_results"],
        doc["artifacts"]["findings"],
        doc["artifacts"]["poam_items"],
        doc["artifacts"]["evidence_links"],
        doc["artifacts"]["reconciliation"],
        doc["artifacts"]["assessor_report"],
        doc["artifacts"]["executive_report"],
        doc["artifacts"]["ao_report"],
        doc["artifacts"]["reconciliation_report"],
    ):
        assert rel
        assert (pkg / rel).is_file(), rel

    manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
    paths_in_manifest = {f["path"] for f in manifest["files"]}
    assert "checksums.sha256" in paths_in_manifest
    assert "fedramp20x-package.json" in paths_in_manifest


def test_top_package_automation_percentage(tmp_path: Path) -> None:
    paths = _write_fixtures(tmp_path)
    pkg = tmp_path / "package"
    doc = build_fedramp20x_package(
        package_output=pkg,
        system_boundary_path=paths["system_boundary"],
        authorization_scope_path=paths["authorization_scope"],
        ksi_catalog_path=paths["ksi_catalog"],
        ksi_results_path=paths["ksi_results"],
        findings_path=paths["findings"],
        poam_items_path=paths["poam"],
        evidence_graph_path=paths["graph"],
        eval_results_path=paths["eval"],
        evidence_registry_path=paths["evidence_registry"],
        report_paths=None,
        fail_on_validation=True,
    )
    # 1 automated of 2 catalog KSIs
    assert doc["summary"]["total_ksis"] == 2
    assert doc["summary"]["automated_ksis"] == 1
    assert doc["summary"]["automation_percentage"] == 50.0


def test_top_package_open_finding_requires_poam(tmp_path: Path) -> None:
    paths = _write_fixtures(tmp_path)
    findings = [
        {
            "finding_id": "F-1",
            "status": "open",
            "severity": "high",
            "linked_ksi_ids": ["KSI-AUTO"],
        }
    ]
    paths["findings"].write_text(json.dumps({"findings": findings}), encoding="utf-8")

    with pytest.raises(Fedramp20xPackageValidationError, match="POA&M"):
        build_fedramp20x_package(
            package_output=tmp_path / "package",
            system_boundary_path=paths["system_boundary"],
            authorization_scope_path=paths["authorization_scope"],
            ksi_catalog_path=paths["ksi_catalog"],
            ksi_results_path=paths["ksi_results"],
            findings_path=paths["findings"],
            poam_items_path=paths["poam"],
            evidence_graph_path=paths["graph"],
            eval_results_path=paths["eval"],
            evidence_registry_path=paths["evidence_registry"],
            report_paths=None,
        )


def test_top_package_open_finding_satisfied_by_poam_row(tmp_path: Path) -> None:
    paths = _write_fixtures(tmp_path)
    findings = [
        {
            "finding_id": "F-1",
            "status": "open",
            "severity": "high",
            "linked_ksi_ids": ["KSI-AUTO"],
        }
    ]
    poam = [{"finding_id": "F-1", "status": "open", "poam_id": "P-1"}]
    paths["findings"].write_text(json.dumps({"findings": findings}), encoding="utf-8")
    paths["poam"].write_text(json.dumps({"poam_items": poam}), encoding="utf-8")

    doc = build_fedramp20x_package(
        package_output=tmp_path / "package",
        system_boundary_path=paths["system_boundary"],
        authorization_scope_path=paths["authorization_scope"],
        ksi_catalog_path=paths["ksi_catalog"],
        ksi_results_path=paths["ksi_results"],
        findings_path=paths["findings"],
        poam_items_path=paths["poam"],
        evidence_graph_path=paths["graph"],
        eval_results_path=paths["eval"],
        evidence_registry_path=paths["evidence_registry"],
        report_paths=None,
    )
    assert doc["summary"]["open_poam_items"] == 1


def test_top_package_fail_ksi_requires_finding_or_exception(tmp_path: Path) -> None:
    paths = _write_fixtures(tmp_path)
    ksi = json.loads(paths["ksi_results"].read_text(encoding="utf-8"))
    ksi["ksi_results"][0]["status"] = "FAIL"
    paths["ksi_results"].write_text(json.dumps(ksi), encoding="utf-8")

    with pytest.raises(Fedramp20xPackageValidationError, match="KSI-AUTO"):
        build_fedramp20x_package(
            package_output=tmp_path / "package",
            system_boundary_path=paths["system_boundary"],
            authorization_scope_path=paths["authorization_scope"],
            ksi_catalog_path=paths["ksi_catalog"],
            ksi_results_path=paths["ksi_results"],
            findings_path=paths["findings"],
            poam_items_path=paths["poam"],
            evidence_graph_path=paths["graph"],
            eval_results_path=paths["eval"],
            evidence_registry_path=paths["evidence_registry"],
            report_paths=None,
        )


def test_top_package_missing_evidence_graph_file_still_builds(tmp_path: Path) -> None:
    paths = _write_fixtures(tmp_path)
    paths["graph"].unlink()
    pkg = tmp_path / "package"
    doc = build_fedramp20x_package(
        package_output=pkg,
        system_boundary_path=paths["system_boundary"],
        authorization_scope_path=paths["authorization_scope"],
        ksi_catalog_path=paths["ksi_catalog"],
        ksi_results_path=paths["ksi_results"],
        findings_path=paths["findings"],
        poam_items_path=paths["poam"],
        evidence_graph_path=paths["graph"],
        eval_results_path=paths["eval"],
        evidence_registry_path=paths["evidence_registry"],
        report_paths=None,
    )
    assert (pkg / "artifacts" / "evidence_graph.json").is_file()
    assert json.loads((pkg / "artifacts" / "evidence_graph.json").read_text(encoding="utf-8")) == {}
