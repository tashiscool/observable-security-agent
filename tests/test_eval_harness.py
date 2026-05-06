"""Tests for the offline Observable Security Agent eval harness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.eval_harness import DEFAULT_EVAL_FIXTURE, load_eval_cases, run_eval_case, run_eval_harness


def test_builtin_eval_fixture_contains_required_cases() -> None:
    cases = load_eval_cases(DEFAULT_EVAL_FIXTURE)

    assert len(cases) == 15
    assert {case["evalId"] for case in cases} >= {
        "EVAL-001",
        "EVAL-007",
        "EVAL-012",
        "EVAL-013",
        "EVAL-015",
    }
    for case in cases:
        assert {"controls", "evidence", "findings", "humanReviews"} <= set(case["inputs"])
        assert {"assessmentStatuses", "requiredRecommendations", "blockedClaims", "missingEvidenceControls", "guardrailFailures"} <= set(case["expected"])


def test_each_builtin_eval_case_passes() -> None:
    results = [run_eval_case(case) for case in load_eval_cases(DEFAULT_EVAL_FIXTURE)]

    assert all(result.passed for result in results), [r.eval_id for r in results if not r.passed]
    by_id = {result.eval_id: result for result in results}
    assert by_id["EVAL-002"].actual["missingEvidenceControls"] == ["AC-2"]
    assert "account_boundary" in by_id["EVAL-007"].actual["guardrailFailures"]
    assert "prompt_injection" in by_id["EVAL-012"].actual["guardrailWarnings"]
    assert "unsupported_compliance_claim" in by_id["EVAL-013"].actual["blockedClaims"]


def test_eval_harness_writes_json_and_markdown(tmp_path: Path) -> None:
    doc = run_eval_harness(output_dir=tmp_path)

    assert doc["summary"] == {"total": 15, "passed": 15, "failed": 0}
    results_path = tmp_path / "eval_results.json"
    summary_path = tmp_path / "eval_summary.md"
    assert results_path.is_file()
    assert summary_path.is_file()
    data = json.loads(results_path.read_text(encoding="utf-8"))
    assert data["summary"]["failed"] == 0
    assert "# Observable Security Agent eval summary" in summary_path.read_text(encoding="utf-8")


def test_run_evals_cli(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "agent.py", "run-evals", "--output-dir", str(tmp_path)],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Passed:  15/15" in proc.stdout
    assert (tmp_path / "eval_results.json").is_file()
    assert (tmp_path / "eval_summary.md").is_file()
