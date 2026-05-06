"""Tests for ``scripts/validate_outputs.py`` (evidence package validation)."""

from __future__ import annotations

import json
import csv
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"
VALIDATE = ROOT / "scripts" / "validate_outputs.py"


def _run_validate(output_dir: Path, *, mode: str = "demo") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATE), "--output-dir", str(output_dir), "--mode", mode],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


def _run_assess(output_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(output_dir),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


def test_validate_outputs_script_passes_after_fixture_assess(tmp_path: Path) -> None:
    a = _run_assess(tmp_path)
    assert a.returncode == 0, a.stderr + a.stdout
    v = _run_validate(tmp_path)
    assert v.returncode == 0, v.stderr + v.stdout
    assert "VALIDATION PASSED" in v.stdout
    assert v.stderr == ""


def test_validate_outputs_fails_when_evidence_graph_removed(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    (tmp_path / "evidence_graph.json").unlink()
    v = _run_validate(tmp_path)
    assert v.returncode == 1
    assert "Missing required artifact" in v.stderr


def test_validate_outputs_fails_when_graph_has_no_edges(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    (tmp_path / "evidence_graph.json").write_text(
        json.dumps({"version": "1.0", "nodes": {"inventory": [{"id": "x"}]}, "edges": []}),
        encoding="utf-8",
    )
    v = _run_validate(tmp_path)
    assert v.returncode == 1
    assert "edges must be a non-empty array" in v.stderr


def test_validate_outputs_fails_when_eval_results_missing_required_eval(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    drop = "CM8_INVENTORY_RECONCILIATION"
    data["evaluations"] = [e for e in data["evaluations"] if e.get("eval_id") != drop]
    recs = data.get("eval_result_records")
    if isinstance(recs, list):
        data["eval_result_records"] = [e for e in recs if e.get("eval_id") != drop]
    (tmp_path / "eval_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    v = _run_validate(tmp_path)
    assert v.returncode == 1
    assert "missing required eval_id" in v.stderr
    assert "CM8_INVENTORY_RECONCILIATION" in v.stderr


def test_validate_outputs_help_documents_default_output_dir() -> None:
    p = subprocess.run(
        [sys.executable, str(VALIDATE), "-h"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert p.returncode == 0
    assert "--output-dir" in p.stdout
    low = p.stdout.lower()
    assert "output" in low
    assert "default" in low


def test_validate_outputs_fails_when_no_fail_evaluation(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    for e in data["evaluations"]:
        e["result"] = "PASS"
    (tmp_path / "eval_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    v = _run_validate(tmp_path)
    assert v.returncode == 1
    assert "at least one evaluation with result FAIL" in v.stderr


def test_validate_outputs_live_allows_all_pass_and_no_generated_poam(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    for e in data["evaluations"]:
        e["result"] = "PASS"
    (tmp_path / "eval_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (tmp_path / "poam.csv").write_text(
        "poam_id,weakness_name,controls,raw_severity,status,asset_identifier,notes\n",
        encoding="utf-8",
    )

    demo = _run_validate(tmp_path, mode="demo")
    live = _run_validate(tmp_path, mode="live")

    assert demo.returncode == 1
    assert "POAM-AUTO" in demo.stderr
    assert live.returncode == 0, live.stderr + live.stdout
    assert "VALIDATION PASSED" in live.stdout


def test_validate_outputs_fails_when_assessor_findings_removed(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    for e in data["evaluations"]:
        if e.get("result") in ("FAIL", "PARTIAL"):
            e.pop("assessor_findings", None)
            break
    (tmp_path / "eval_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    v = _run_validate(tmp_path)

    assert v.returncode == 1
    assert "missing assessor_findings" in v.stderr


def test_validate_outputs_fails_when_record_assessor_findings_removed(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    data = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    for e in data.get("eval_result_records") or []:
        if e.get("result") in ("FAIL", "PARTIAL"):
            e.pop("assessor_findings", None)
            break
    (tmp_path / "eval_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    v = _run_validate(tmp_path)

    assert v.returncode == 1
    assert "eval_result_records" in v.stderr
    assert "missing assessor_findings" in v.stderr


def test_validate_outputs_fails_when_gap_matrix_loses_assessor_columns(tmp_path: Path) -> None:
    assert _run_assess(tmp_path).returncode == 0
    matrix = tmp_path / "evidence_gap_matrix.csv"
    rows = list(csv.DictReader(matrix.read_text(encoding="utf-8").splitlines()))
    assert rows
    keep = [h for h in (rows[0].keys()) if h not in {"current_state", "target_state", "priority", "estimated_effort", "remediation_steps"}]
    with matrix.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keep)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in keep})

    v = _run_validate(tmp_path)

    assert v.returncode == 1
    assert "evidence_gap_matrix.csv: missing assessor column" in v.stderr
