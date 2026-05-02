"""Bounded autonomous agent loop (run-agent)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agent_loop.policy import AUTONOMOUS_ACTION_IDS, classify_action

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def test_blocked_categories_not_autonomous() -> None:
    d = classify_action("cloud_remediation.apply_patch")
    assert not d.allowed
    assert d.category == "blocked"


def test_unknown_action_fail_closed() -> None:
    assert not classify_action("invoke_skynet").allowed


def test_playbook_actions_in_allowlist() -> None:
    for aid in (
        "assess_run_evals",
        "draft_tickets_json_only",
        "validate_20x_package",
        "write_trace_json",
    ):
        assert aid in AUTONOMOUS_ACTION_IDS


def test_run_agent_cli_writes_trace_and_summary(tmp_path: Path) -> None:
    out = tmp_path / "out"
    pkg = tmp_path / "pkg"
    r = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "run-agent",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_agentic_risk",
            "--output-dir",
            str(out),
            "--package-output",
            str(pkg),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    trace = out / "agent_run_trace.json"
    summ = out / "agent_run_summary.md"
    assert trace.is_file()
    assert summ.is_file()
    doc = json.loads(trace.read_text(encoding="utf-8"))
    assert doc.get("bounded_playbook") is True
    assert any(s.get("phase") == "observe" for s in doc.get("steps", []))
    assert any(s.get("phase") == "plan" for s in doc.get("steps", []))
    assert any(s.get("chosen_action") == "assess_run_evals" for s in doc.get("steps", []))
    assert (out / "agent_draft_tickets.json").is_file()
    text = summ.read_text(encoding="utf-8")
    assert "Policy" in text or "policy" in text
