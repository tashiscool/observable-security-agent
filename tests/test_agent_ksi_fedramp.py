"""FedRAMP 20x agent KSI catalog, mapping, and package integration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from fedramp20x.eval_ksi_mapping import eval_to_ksi_ids
from fedramp20x.finding_builder import build_findings

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
MAPPINGS = ROOT / "mappings"
AGENT = ROOT / "agent.py"


def test_eval_to_ksi_ids_merges_agent_program_ksis() -> None:
    cfg = yaml.safe_load((CONFIG / "control-crosswalk.yaml").read_text(encoding="utf-8"))
    agent_map = cfg.get("eval_id_agent_ksi") or {}
    import csv

    rows = list(csv.DictReader((MAPPINGS / "rev5-to-20x-ksi-crosswalk.csv").read_text(encoding="utf-8").splitlines()))
    ev = {
        "eval_id": "AGENT_TOOL_GOVERNANCE",
        "control_refs": ["AC-6", "CM-10"],
        "result": "FAIL",
    }
    ids = eval_to_ksi_ids(ev, rows, dict(cfg.get("eval_id_default_ksi") or {}), agent_map)
    assert "KSI-AGENT-02" in ids
    assert "KSI-AGENT-04" in ids


def test_failed_agent_eval_finding_links_agent_ksi_and_poam() -> None:
    import csv

    rows = list(csv.DictReader((MAPPINGS / "rev5-to-20x-ksi-crosswalk.csv").read_text(encoding="utf-8").splitlines()))
    cfg = yaml.safe_load((CONFIG / "control-crosswalk.yaml").read_text(encoding="utf-8"))
    agent_map = cfg.get("eval_id_agent_ksi") or {}
    edef = dict(cfg.get("eval_id_default_ksi") or {})
    rev4 = list(csv.DictReader((MAPPINGS / "rev4-to-rev5-crosswalk.csv").read_text(encoding="utf-8").splitlines()))
    ev = {
        "eval_id": "AGENT_PERMISSION_SCOPE",
        "result": "FAIL",
        "name": "Agent permission scope",
        "control_refs": ["AC-2", "AC-3"],
        "severity": "high",
        "summary": "Scope failure",
        "gap": "Wildcard admin credential detected for agent support-ticket-agent.",
        "gaps": ["Wildcard admin credential detected for agent support-ticket-agent."],
        "evidence": ["agent_assessment.json shows wildcard admin tool target."],
        "recommended_action": "Remove wildcard admin; scope tools to explicit resources.",
        "affected_assets": ["support-ticket-agent"],
    }
    poam_items = [
        {
            "poam_id": "POAM-AUTO-AGENT_PERMISSION_SCOPE-001",
            "source_eval_id": "AGENT_PERMISSION_SCOPE",
            "title": "Fix agent scope",
            "status": "open",
        }
    ]
    findings = build_findings(
        [ev],
        rev4_to_rev5=rev4,
        rev5_to_ksi=rows,
        eval_default_ksi=edef,
        eval_agent_ksi=agent_map,
        poam_items=poam_items,
    )
    assert findings
    f0 = findings[0]
    assert "KSI-AGENT-01" in (f0.get("linked_ksi_ids") or [])
    assert f0.get("poam_id") == "POAM-AUTO-AGENT_PERMISSION_SCOPE-001"
    assert "agent_eval_results.json" in str(f0.get("source_artifact_refs"))


def test_scenario_agentic_risk_builds_package_with_agent_ksi_results(tmp_path: Path) -> None:
    out = tmp_path / "assess"
    pkg = tmp_path / "package"
    r1 = subprocess.run(
        [
            sys.executable,
            str(AGENT),
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
    )
    assert r1.returncode == 0, r1.stderr + r1.stdout
    r2 = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "build-20x-package",
            "--assessment-output",
            str(out),
            "--config",
            str(CONFIG),
            "--package-output",
            str(pkg),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r2.returncode == 0, r2.stderr + r2.stdout
    doc = json.loads((pkg / "fedramp20x-package.json").read_text(encoding="utf-8"))
    kids = {r.get("ksi_id") for r in doc.get("ksi_validation_results", []) if r.get("ksi_id")}
    for kid in ("KSI-AGENT-01", "KSI-AGENT-02", "KSI-AGENT-03", "KSI-AGENT-04"):
        assert kid in kids
    agent_fail = [f for f in doc.get("findings", []) if "AGENT_" in ",".join(f.get("linked_eval_ids") or [])]
    assert agent_fail, "expected findings from agent FAIL evals"
    assert any("KSI-AGENT" in ",".join(f.get("linked_ksi_ids") or []) for f in agent_fail)
    poam_rows = doc.get("poam_items") or []
    assert any(str(p.get("source_eval_id", "")).startswith("AGENT_") for p in poam_rows)


def test_web_sample_20x_package_includes_agent_ksi_catalog() -> None:
    """FedRAMP 20x tab fallback (web/sample-data/20x-package/) lists agent KSIs like the explorer."""
    p = ROOT / "web" / "sample-data" / "20x-package" / "fedramp20x-package.json"
    assert p.is_file(), "run agent build + slim export or keep sample in repo"
    doc = json.loads(p.read_text(encoding="utf-8"))
    cat_ids = {k["ksi_id"] for k in doc.get("ksi_catalog", []) if k.get("ksi_id")}
    assert {"KSI-AGENT-01", "KSI-AGENT-02", "KSI-AGENT-03", "KSI-AGENT-04"} <= cat_ids
    res_ids = {r["ksi_id"] for r in doc.get("ksi_validation_results", []) if r.get("ksi_id")}
    assert {"KSI-AGENT-01", "KSI-AGENT-02", "KSI-AGENT-03", "KSI-AGENT-04"} <= res_ids
