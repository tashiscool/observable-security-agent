"""JSON Schema validation for FedRAMP 20x packages and artifacts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fedramp20x.package_builder import build_fedramp20x_package
from fedramp20x.schema_validator import validate_json_file, validate_package

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
AGENT = ROOT / "agent.py"


def _fixture_paths(tmp: Path) -> dict[str, Path]:
    """Minimal config + assessment inputs (same shape as test_fedramp20x_top_package)."""
    from tests.test_fedramp20x_top_package import _write_fixtures

    return _write_fixtures(tmp)


def test_validate_package_top_level_passes(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    pkg = tmp_path / "evidence" / "package"
    build_fedramp20x_package(
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
    rep = validate_package(pkg / "fedramp20x-package.json", SCHEMAS)
    assert rep.valid, rep.errors


def test_validate_package_missing_required_field_fails(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    pkg = tmp_path / "evidence" / "package"
    build_fedramp20x_package(
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
    primary = pkg / "fedramp20x-package.json"
    doc = json.loads(primary.read_text(encoding="utf-8"))
    del doc["package_id"]
    primary.write_text(json.dumps(doc), encoding="utf-8")
    rep = validate_package(primary, SCHEMAS)
    assert not rep.valid
    assert any(
        "package_id" in e.lower() or "required" in e.lower() or "not valid under any of the given schemas" in e.lower()
        for e in rep.errors
    )


def test_validate_package_invalid_ksi_status_in_artifact_fails(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    pkg = tmp_path / "evidence" / "package"
    build_fedramp20x_package(
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
    ksi_path = pkg / "artifacts" / "ksi_results.json"
    data = json.loads(ksi_path.read_text(encoding="utf-8"))
    data["ksi_results"][0]["status"] = "BOGUS"
    ksi_path.write_text(json.dumps(data), encoding="utf-8")
    rep = validate_package(pkg / "fedramp20x-package.json", SCHEMAS)
    assert not rep.valid
    assert any("BOGUS" in e or "enum" in e.lower() for e in rep.errors)


def test_validate_package_invalid_finding_severity_fails(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    paths["findings"].write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "finding_id": "F-1",
                        "severity": "CATASTROPHIC",
                        "title": "t",
                        "description": "d",
                        "linked_ksi_ids": ["KSI-AUTO"],
                        "status": "open",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    paths["poam"].write_text(json.dumps({"poam_items": [{"poam_id": "P-1", "finding_id": "F-1"}]}), encoding="utf-8")

    pkg = tmp_path / "evidence" / "package"
    build_fedramp20x_package(
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
    rep = validate_package(pkg / "fedramp20x-package.json", SCHEMAS)
    assert not rep.valid
    assert any("severity" in e.lower() or "enum" in e.lower() for e in rep.errors)


def test_validate_json_file_assessment_summary(tmp_path: Path) -> None:
    p = tmp_path / "assessment_summary.json"
    p.write_text(
        json.dumps(
            {
                "assessment_bundle": "present",
                "eval_pass": 1,
                "eval_fail": 0,
                "eval_partial": 0,
                "eval_open": 0,
                "poam_rows_generated": 0,
                "assets": 1,
            }
        ),
        encoding="utf-8",
    )
    rep = validate_json_file(SCHEMAS / "assessment-summary.schema.json", p)
    assert rep.valid, rep.errors


def test_cli_validate_20x_package_zero_exit(tmp_path: Path) -> None:
    paths = _fixture_paths(tmp_path)
    pkg = tmp_path / "evidence" / "package"
    build_fedramp20x_package(
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
    r = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "validate-20x-package",
            "--package",
            str(pkg / "fedramp20x-package.json"),
            "--schemas",
            str(SCHEMAS),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr + r.stdout
