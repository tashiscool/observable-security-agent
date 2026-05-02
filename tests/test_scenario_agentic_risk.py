"""Fixture scenario ``scenario_agentic_risk`` — agent telemetry + assess CLI agent-security outputs."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.utils import load_evidence_bundle_from_directory, build_asset_evidence
from core.normalizer import load_normalized_primary_event
from core.evaluator import run_evaluations
from evals.agent_eval_support import load_agent_assessment_bundle

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "fixtures" / "scenario_agentic_risk"


def test_load_agent_assessment_from_split_fixture_files() -> None:
    ab = load_agent_assessment_bundle(SCENARIO)
    assert ab is not None
    assert {i.agent_id for i in ab.agent_identities} == {"support-ticket-agent"}
    assert any(tc.tool_name == "cloud_admin_tool" for tc in ab.tool_calls)


def test_agentic_risk_eval_outcomes() -> None:
    bundle = load_evidence_bundle_from_directory(SCENARIO)
    sem, _ = load_normalized_primary_event(bundle)
    cb = run_evaluations(bundle, sem, build_asset_evidence(bundle, sem.asset_id), output_dir=None)
    by_id = {r.eval_id: r.result.value for r in cb.eval_results}
    assert by_id["AGENT_TOOL_GOVERNANCE"] == "FAIL"
    assert by_id["AGENT_PERMISSION_SCOPE"] == "FAIL"
    assert by_id["AGENT_MEMORY_CONTEXT_SAFETY"] == "FAIL"
    assert by_id["AGENT_APPROVAL_GATES"] == "FAIL"
    assert by_id["AGENT_POLICY_VIOLATIONS"] == "FAIL"
    assert by_id["AGENT_AUDITABILITY"] == "PARTIAL"


def test_assess_scenario_agentic_risk_writes_agent_security_artifacts(tmp_path: Path) -> None:
    out = tmp_path / "out"
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_agentic_risk",
            "--include-agent-security",
            "--output-dir",
            str(out),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    for name in (
        "agent_eval_results.json",
        "agent_risk_report.md",
        "agent_threat_hunt_findings.json",
        "agent_poam.csv",
        "secure_agent_architecture.md",
    ):
        assert (out / name).is_file(), f"missing {name}"
    assert "support-ticket-agent" in (out / "secure_agent_architecture.md").read_text(encoding="utf-8")
    data = json.loads((out / "agent_eval_results.json").read_text(encoding="utf-8"))
    ids = {e.get("eval_id") for e in data.get("evaluations", []) if isinstance(e, dict)}
    assert ids == {
        "AGENT_TOOL_GOVERNANCE",
        "AGENT_PERMISSION_SCOPE",
        "AGENT_MEMORY_CONTEXT_SAFETY",
        "AGENT_APPROVAL_GATES",
        "AGENT_POLICY_VIOLATIONS",
        "AGENT_AUDITABILITY",
    }
    hunt = json.loads((out / "agent_threat_hunt_findings.json").read_text(encoding="utf-8"))
    assert isinstance(hunt.get("findings"), list) and len(hunt["findings"]) >= 1
