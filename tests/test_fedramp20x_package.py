"""FedRAMP 20x package build + JSON Schema validation."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def test_build_20x_package_validates(tmp_path: Path) -> None:
    out = tmp_path / "output"
    pkg = tmp_path / "evidence" / "package"
    out.mkdir(parents=True)
    a = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(out),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert a.returncode == 0, a.stderr + a.stdout

    b = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "build-20x-package",
            "--assessment-output",
            str(out),
            "--config",
            str(ROOT / "config"),
            "--package-output",
            str(pkg),
            "--validation-artifact-root",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert b.returncode == 0, b.stderr + b.stdout

    assert (tmp_path / "evidence" / "validation-results" / "poam-items.json").is_file()
    assert (tmp_path / "evidence" / "validation-results" / "evidence-links.json").is_file()
    assert (tmp_path / "evidence" / "package" / "checksums.sha256").is_file()
    chk = (tmp_path / "evidence" / "package" / "checksums.sha256").read_text(encoding="utf-8")
    assert "evidence/validation-results/evidence-links.json" in chk
    el_doc = json.loads((tmp_path / "evidence" / "validation-results" / "evidence-links.json").read_text(encoding="utf-8"))
    assert el_doc.get("schema_version") == "1.0"
    assert isinstance(el_doc.get("evidence_links"), list)
    assert (pkg / "evidence" / "validation-results" / "evidence-links.json").is_file()
    assert (pkg / "evidence" / "package" / "checksums.sha256").is_file()
    assert (tmp_path / "evidence" / "validation-results" / "reconciliation.json").is_file()
    assert (tmp_path / "reports" / "assessor" / "reconciliation-summary.md").is_file()
    assert (tmp_path / "reports" / "assessor" / "poam.md").is_file()

    primary = pkg / "fedramp20x-package.json"
    assert primary.is_file()
    data = json.loads(primary.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["reconciliation_summary"]["parity_status"] == "aligned"
    pm = data.get("package_metadata") or {}
    assert pm.get("package_manifest", {}).get("validation_artifacts_relative")
    assert pm.get("validation_run", {}).get("schema_validation_outcome") == "passed"
    assert pm.get("input_artifact_manifest")
    assert pm.get("tool_version")
    assert pm.get("framework_control_summary", {}).get("catalog_ksi_count", 0) > 0
    assessor_summary = (pkg / "reports" / "assessor" / "assessor-summary.md").read_text(encoding="utf-8")
    assert "Evidence index" in assessor_summary
    assert "evidence-index.md" in assessor_summary
    exec_sum = (pkg / "reports" / "executive" / "executive-summary.md").read_text(encoding="utf-8")
    assert "## Readiness decision" in exec_sum
    ao_brief = (pkg / "reports" / "agency-ao" / "ao-risk-brief.md").read_text(encoding="utf-8")
    assert "residual-risk-register.md" in ao_brief
    assert "customer-responsibility-matrix.md" in ao_brief
    assert (pkg / "reports" / "assessor" / "assessor-summary.md").is_file()
    assert (pkg / "reports" / "machine-readable" / "fedramp20x-package.json").is_file()

    from fedramp20x.schema_validator import validate_package

    rep = validate_package(primary, ROOT / "schemas")
    assert rep.valid, "\n".join(rep.errors)

    shutil.rmtree(pkg, ignore_errors=True)
