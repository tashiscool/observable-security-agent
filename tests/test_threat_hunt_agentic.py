"""CLI and library tests for ``agent.py threat-hunt`` (agentic AI risk)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from core.utils import load_evidence_bundle_from_directory
from core.threat_hunt_agentic import load_agent_bundle_for_hunt, run_agentic_threat_hunt

ROOT = Path(__file__).resolve().parents[1]
AGENTIC = ROOT / "fixtures" / "scenario_agentic_risk"
PUBLIC = ROOT / "fixtures" / "scenario_public_admin_vuln_event"


def test_threat_hunt_fixture_prompt_injection_and_unauthorized_tool_findings(tmp_path: Path) -> None:
    bundle = load_evidence_bundle_from_directory(AGENTIC)
    ab = load_agent_bundle_for_hunt(AGENTIC)
    assert ab is not None
    paths = run_agentic_threat_hunt(
        evidence_root=AGENTIC,
        agent_telemetry_root=AGENTIC,
        bundle=bundle,
        agent_assessment=ab,
        output_dir=tmp_path,
    )
    assert len(paths) == 4
    data = json.loads((tmp_path / "threat_hunt_findings.json").read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    types = {f.get("detection_type") for f in findings}
    assert "prompt_injection_suspected" in types
    assert any(
        f.get("detection_type") == "credential_misuse"
        and "unauthorized" in " ".join(f.get("signals_observed") or []).lower()
        for f in findings
    )
    assert (tmp_path / "threat_hunt_timeline.md").is_file()
    assert (tmp_path / "threat_hunt_queries.md").is_file()
    assert (tmp_path / "agentic_risk_poam.csv").is_file()


def test_threat_hunt_instrumentation_when_no_agentic_alert_rules(tmp_path: Path) -> None:
    """Policy violations present + alert_rules without agentic coverage → instrumentation_gap."""
    bundle = load_evidence_bundle_from_directory(AGENTIC)
    ab = load_agent_bundle_for_hunt(AGENTIC)
    paths = run_agentic_threat_hunt(
        evidence_root=AGENTIC,
        agent_telemetry_root=AGENTIC,
        bundle=bundle,
        agent_assessment=ab,
        output_dir=tmp_path,
    )
    assert paths
    doc = json.loads((tmp_path / "threat_hunt_findings.json").read_text(encoding="utf-8"))
    inst = [f for f in doc["findings"] if f.get("detection_type") == "instrumentation_gap"]
    assert inst, "expected instrumentation_gap finding"
    instr = str(inst[0].get("recommended_instrumentation", "")).lower()
    assert "siem" in instr or "alert" in instr or "correlation" in instr


def test_threat_hunt_cli_fixture_scenario(tmp_path: Path) -> None:
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "threat-hunt",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_agentic_risk",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert (tmp_path / "threat_hunt_findings.json").is_file()


def test_threat_hunt_cli_aws_raw_with_separate_agent_telemetry(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    shutil.copytree(PUBLIC, raw)
    out = tmp_path / "out"
    r = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "threat-hunt",
            "--provider",
            "aws",
            "--raw-evidence-dir",
            str(raw),
            "--agent-telemetry",
            str(AGENTIC),
            "--output-dir",
            str(out),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    doc = json.loads((out / "threat_hunt_findings.json").read_text(encoding="utf-8"))
    assert doc.get("finding_count", 0) >= 1
