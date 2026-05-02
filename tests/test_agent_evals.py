"""Agent-assessment evals (telemetry governance)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.agent_models import AgentAssessmentBundle, AgentIdentity, AgentToolCall
from evals.agent_eval_support import (
    run_agent_approval_gates,
    run_agent_tool_governance,
)
from evals.agent_tool_governance import EVAL_ID as TOOL_GOV_ID

ROOT = Path(__file__).resolve().parents[1]


def test_run_agent_tool_governance_fails_on_disallowed_tool() -> None:
    ab = AgentAssessmentBundle(
        agent_identities=[
            AgentIdentity(
                agent_id="a1",
                name="n",
                owner="o",
                environment="dev",
                purpose="p",
                allowed_tools=["safe_tool"],
                allowed_data_scopes=["s3://ok/"],
                allowed_actions=["read"],
                human_approval_required_for=[],
                credentials_ref="vault://a1",
                created_at=datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
            )
        ],
        tool_calls=[
            AgentToolCall(
                call_id="c1",
                agent_id="a1",
                timestamp=datetime(2026, 5, 1, 1, 0, 0, tzinfo=timezone.utc),
                tool_name="danger_tool",
                action="read",
                target_resource="s3://ok/x",
                input_summary="i",
                output_summary="o",
                risk_level="low",
                approval_required=False,
                approval_status="not_required",
                policy_decision="allowed",
                raw_ref="r1",
            )
        ],
    )
    er = run_agent_tool_governance(ab)
    assert er.result == "FAIL"
    assert "danger_tool" in " ".join(er.gaps).lower()


def test_run_agent_approval_gates_detects_missing_approval() -> None:
    ab = AgentAssessmentBundle(
        agent_identities=[
            AgentIdentity(
                agent_id="a1",
                name="n",
                owner="o",
                environment="dev",
                purpose="p",
                allowed_tools=["t"],
                allowed_data_scopes=[],
                allowed_actions=["read"],
                human_approval_required_for=[],
                credentials_ref=None,
                created_at=datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
            )
        ],
        tool_calls=[
            AgentToolCall(
                call_id="c2",
                agent_id="a1",
                timestamp=datetime(2026, 5, 1, 2, 0, 0, tzinfo=timezone.utc),
                tool_name="t",
                action="read",
                target_resource=None,
                input_summary="i",
                output_summary="o",
                risk_level="high",
                approved_by=None,
                approval_required=True,
                approval_status="missing",
                policy_decision="allowed",
                raw_ref="r2",
            )
        ],
    )
    er = run_agent_approval_gates(ab)
    assert er.result == "FAIL"
    assert any("approval" in g.lower() for g in er.gaps)


def test_assess_fixture_emits_agent_eval_rows(tmp_path: Path) -> None:
    scen = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    work = tmp_path / "scenario"
    shutil.copytree(scen, work)
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "assess",
            "--provider",
            "fixture",
            "--fixture-dir",
            str(work),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    data = json.loads((tmp_path / "out" / "eval_results.json").read_text(encoding="utf-8"))
    ids = {e.get("eval_id") for e in data.get("evaluations", []) if isinstance(e, dict)}
    assert TOOL_GOV_ID in ids
    agent_row = next(e for e in data["evaluations"] if e.get("eval_id") == TOOL_GOV_ID)
    assert str(agent_row.get("result", "")).upper() in ("PASS", "FAIL", "PARTIAL")


def test_fixtures_agent_security_pass_bundle_from_disk() -> None:
    """Representative JSON under fixtures/agent_security/ (used by copying into scenarios)."""
    p = ROOT / "fixtures" / "agent_security" / "agent_assessment_pass.json"
    assert p.is_file()
    ab = AgentAssessmentBundle.model_validate_json(p.read_text(encoding="utf-8"))
    er = run_agent_tool_governance(ab)
    assert er.result == "PASS"
