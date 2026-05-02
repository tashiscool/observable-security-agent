from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def _run_agent(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AGENT), *argv],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def test_assess_fixture_cli_public_admin_scenario(tmp_path: Path) -> None:
    r = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Multi-Cloud Security Evidence Agent" in r.stdout
    assert "Scenario: scenario_public_admin_vuln_event" in r.stdout
    assert "[FAIL] CM-8 Inventory Reconciliation" in r.stdout
    assert "[OPEN] CA-5 POA&M rows generated" in r.stdout
    assert (tmp_path / "eval_results.json").is_file()
    assert (tmp_path / "evidence_graph.json").is_file()
    assert (tmp_path / "correlation_report.md").is_file()
    assert (tmp_path / "instrumentation_plan.md").is_file()
    assert (tmp_path / "agent_instrumentation_plan.md").is_file()
    assert (tmp_path / "poam.csv").is_file()
    assert (tmp_path / "evidence_gap_matrix.csv").is_file()
    assert (tmp_path / "assessment_summary.json").is_file()
    assert "assessment_summary.json" in r.stdout


def test_assess_fixture_uses_fixture_dir_instead_of_scenario_name(tmp_path: Path) -> None:
    fixture = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--fixture-dir",
            str(fixture),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Scenario: scenario_public_admin_vuln_event" in r.stdout
    assert (tmp_path / "eval_results.json").is_file()


def test_assess_default_scenario_when_omitted(tmp_path: Path) -> None:
    r = _run_agent(
        ["assess", "--provider", "fixture", "--output-dir", str(tmp_path)],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Scenario: scenario_public_admin_vuln_event" in r.stdout


def test_validate_after_assess(tmp_path: Path) -> None:
    a = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert a.returncode == 0, a.stderr
    v = _run_agent(["validate", "--output-dir", str(tmp_path)], cwd=ROOT)
    assert v.returncode == 0, v.stderr + v.stdout
    assert "VALIDATION PASSED" in v.stdout


def test_list_evals_cli() -> None:
    r = _run_agent(["list-evals"], cwd=ROOT)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "CM8_INVENTORY_RECONCILIATION" in r.stdout
    assert "RA5_SCANNER_SCOPE_COVERAGE" in r.stdout
    assert "Controls:" in r.stdout


def test_report_rerender_from_eval_results(tmp_path: Path) -> None:
    a = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert a.returncode == 0, a.stderr
    out2 = tmp_path / "report_out"
    r = _run_agent(
        ["report", "--input", str(tmp_path / "eval_results.json"), "--output-dir", str(out2)],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert (out2 / "correlation_report.md").is_file()
    assert (out2 / "eval_results.json").is_file()


def test_report_missing_input_returns_nonzero() -> None:
    r = _run_agent(
        ["report", "--input", str(ROOT / "nonexistent_eval_results.json"), "--output-dir", "output"],
        cwd=ROOT,
    )
    assert r.returncode == 2


def test_assess_aws_requires_raw_evidence_dir() -> None:
    r = _run_agent(["assess", "--provider", "aws", "--output-dir", "out"], cwd=ROOT)
    assert r.returncode == 2
    assert "raw-evidence-dir" in r.stderr.lower() or "evidence-dir" in r.stderr.lower()


def test_assess_aws_with_raw_evidence_dir_fixture_layout(tmp_path: Path) -> None:
    raw = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "aws",
            "--raw-evidence-dir",
            str(raw),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert (tmp_path / "eval_results.json").is_file()


def test_assess_aws_deprecated_evidence_dir_alias(tmp_path: Path) -> None:
    raw = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "aws",
            "--evidence-dir",
            str(raw),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
