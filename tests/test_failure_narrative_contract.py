"""Tests for FAIL/PARTIAL evidence-chain narrative enforcement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.failure_narrative_contract import (
    coerce_evaluation_row_to_record,
    infer_remediation_disposition,
    validate_eval_results_fail_partial_contracts,
    validate_fail_partial_record,
)
from core.output_validation import validate_evidence_package

ROOT = Path(__file__).resolve().parents[1]


def test_infer_remediation_disposition_detects_poam_and_risk() -> None:
    assert infer_remediation_disposition(recommended_actions=["Create POA&M if needed"]) == "poam"
    assert infer_remediation_disposition(recommended_actions=["Obtain formal risk acceptance"]) == "risk_acceptance"
    assert (
        infer_remediation_disposition(
            recommended_actions=["POA&M or risk acceptance per policy"],
        )
        == "poam_or_risk_acceptance"
    )


def test_validate_fail_partial_requires_gaps_evidence_actions() -> None:
    bad = {
        "eval_id": "X",
        "result": "FAIL",
        "summary": "s",
        "name": "n",
        "evidence": [],
        "gaps": [],
        "controls": ["CM-8"],
        "recommended_actions": [],
        "remediation_disposition": "poam_or_risk_acceptance",
    }
    errs = validate_fail_partial_record(bad, index=0)
    assert any("evidence" in e for e in errs)
    assert any("gaps" in e for e in errs)
    assert any("recommended_actions" in e for e in errs)


def test_validate_fail_partial_requires_controls_or_ksi() -> None:
    bad = {
        "eval_id": "X",
        "result": "FAIL",
        "summary": "s",
        "name": "n",
        "evidence": ["e1"],
        "gaps": ["g1"],
        "controls": [],
        "linked_ksi_ids": [],
        "recommended_actions": ["do thing"],
        "remediation_disposition": "poam",
    }
    errs = validate_fail_partial_record(bad, index=0)
    assert any("linked_ksi_ids" in e or "control" in e.lower() for e in errs)


def test_coerce_row_splits_gap_and_infers_disposition() -> None:
    row = {
        "eval_id": "E1",
        "result": "FAIL",
        "gap": "a; b",
        "recommended_action": "Create POA&M entry",
        "control_refs": ["RA-5"],
        "evidence": ["scanner export attached"],
    }
    c = coerce_evaluation_row_to_record(row)
    assert c["gaps"] == ["a", "b"]
    assert c["controls"] == ["RA-5"]
    assert c["remediation_disposition"] == "poam"


def test_fixture_assess_eval_results_passes_contract(tmp_path: Path) -> None:
    import subprocess
    import sys

    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    assert validate_eval_results_fail_partial_contracts(data) == []
    errs = validate_evidence_package(tmp_path)
    assert errs == []


def test_eval_results_document_has_remediation_on_records(tmp_path: Path) -> None:
    """Regression: eval_result_records include closure/workpaper fields after assess."""
    import subprocess
    import sys

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    recs = data.get("eval_result_records") or []
    assert recs
    fail = [r for r in recs if str(r.get("result", "")).upper() == "FAIL"]
    assert fail
    for r in fail:
        assert r.get("remediation_disposition") in (
            "poam",
            "risk_acceptance",
            "poam_or_risk_acceptance",
            "none",
        ), r.get("eval_id")
        findings = r.get("assessor_findings")
        assert isinstance(findings, list) and findings, r.get("eval_id")
        assert findings[0].get("current_state")
        assert findings[0].get("target_state")
        assert findings[0].get("remediation_steps")
