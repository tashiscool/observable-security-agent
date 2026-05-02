"""Static checks for web/sample-data — same shapes the Evidence Explorer expects when ../output/ is absent."""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SD = ROOT / "web" / "sample-data"


def test_sample_eval_results_has_full_eval_grid() -> None:
    p = SD / "eval_results.json"
    assert p.is_file()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert "evaluations" in data and isinstance(data["evaluations"], list)
    ids = {str(e.get("eval_id")) for e in data["evaluations"] if isinstance(e, dict)}
    required = {
        "CM8_INVENTORY_RECONCILIATION",
        "RA5_SCANNER_SCOPE_COVERAGE",
        "AU6_CENTRALIZED_LOG_COVERAGE",
        "SI4_ALERT_INSTRUMENTATION",
        "CROSS_DOMAIN_EVENT_CORRELATION",
        "RA5_EXPLOITATION_REVIEW",
        "CM3_CHANGE_EVIDENCE_LINKAGE",
        "AGENT_TOOL_GOVERNANCE",
        "AGENT_PERMISSION_SCOPE",
        "AGENT_MEMORY_CONTEXT_SAFETY",
        "AGENT_APPROVAL_GATES",
        "AGENT_POLICY_VIOLATIONS",
        "AGENT_AUDITABILITY",
        "CA5_POAM_STATUS",
    }
    assert required <= ids, f"missing eval_ids: {sorted(required - ids)}"


def test_sample_evidence_graph_loadable() -> None:
    p = SD / "evidence_graph.json"
    assert p.is_file()
    g = json.loads(p.read_text(encoding="utf-8"))
    assert isinstance(g, dict)
    assert isinstance(g.get("edges"), list) and len(g["edges"]) > 0
    nodes = g.get("nodes")
    assert nodes is not None
    if isinstance(nodes, list):
        assert len(nodes) > 0
    elif isinstance(nodes, dict):
        assert sum(len(v) for v in nodes.values() if isinstance(v, list)) > 0


def test_sample_correlations_json_shape() -> None:
    p = SD / "correlations.json"
    assert p.is_file()
    c = json.loads(p.read_text(encoding="utf-8"))
    assert isinstance(c, dict)
    assert "correlations" in c or "eval_id" in c


def test_sample_agent_instrumentation_plan_md_present() -> None:
    p = SD / "agent_instrumentation_plan.md"
    assert p.is_file()
    t = p.read_text(encoding="utf-8")
    assert "Splunk" in t and "Sentinel" in t
    assert "SIEM gap: prompt injection" in t or "Prompt injection suspected" in t


def test_sample_secure_agent_architecture_md_present() -> None:
    p = SD / "secure_agent_architecture.md"
    assert p.is_file()
    t = p.read_text(encoding="utf-8")
    assert "## 1." in t or "Agent identity" in t
    assert "fixture" in t.lower()


def test_sample_poam_csv_readable() -> None:
    p = SD / "poam.csv"
    assert p.is_file()
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 2
    rows = list(csv.DictReader(lines))
    assert rows


def test_sample_agent_run_trace_for_explorer() -> None:
    p = SD / "agent_run_trace.json"
    assert p.is_file()
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc.get("bounded_playbook") is True
    steps = doc.get("steps")
    assert isinstance(steps, list) and len(steps) >= 3
    phases = {s.get("phase") for s in steps if isinstance(s, dict)}
    assert "observe" in phases and "plan" in phases
    assert any(s.get("phase") == "act" for s in steps if isinstance(s, dict))
    assert "blocked_categories_reference" in doc


def test_sample_agent_run_summary_md_present() -> None:
    p = SD / "agent_run_summary.md"
    assert p.is_file()
    t = p.read_text(encoding="utf-8")
    assert "bounded" in t.lower() or "Bounded" in t
    assert "policy" in t.lower()
